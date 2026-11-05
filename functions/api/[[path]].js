const json = (data, status = 200, extraHeaders = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });

const encoder = new TextEncoder();
const COOKIE_NAME = "finesssim_session";
const SESSION_SECONDS = 60 * 60 * 24 * 7;

const BOOKING_STATUSES = [
  "new",
  "confirmed",
  "completed",
  "cancelled"
];

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function decodeBase64url(value) {
  const normalized = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(normalized + "=".repeat((4 - normalized.length % 4) % 4));
  return Uint8Array.from(binary, char => char.charCodeAt(0));
}

async function signingKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function createSession(secret) {
  const payload = base64url(
    encoder.encode(JSON.stringify({
      role: "owner",
      expires: Math.floor(Date.now() / 1000) + SESSION_SECONDS
    }))
  );

  const key = await signingKey(secret);
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(payload));

  return payload + "." + base64url(new Uint8Array(signature));
}

async function verifySession(request, secret) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp("(?:^|;\\s*)" + COOKIE_NAME + "=([^;]+)"));

  if (!match) return false;

  try {
    const parts = match[1].split(".");
    if (parts.length !== 2) return false;

    const key = await signingKey(secret);
    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      decodeBase64url(parts[1]),
      encoder.encode(parts[0])
    );

    if (!valid) return false;

    const payload = JSON.parse(new TextDecoder().decode(decodeBase64url(parts[0])));
    return payload.role === "owner" &&
      Number.isInteger(payload.expires) &&
      payload.expires > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function sessionCookie(value) {
  return `${COOKIE_NAME}=${value}; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=${SESSION_SECONDS}`;
}

function clearSessionCookie() {
  return `${COOKIE_NAME}=; HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=0`;
}

function safeText(value, maxLength = 500) {
  if (typeof value !== "string") return null;
  const cleaned = value.trim();
  if (cleaned.length > maxLength) return null;
  return cleaned;
}

function validOrigin(request) {
  const origin = request.headers.get("Origin");
  return !origin || origin === new URL(request.url).origin;
}

async function readBody(request) {
  const length = Number(request.headers.get("Content-Length") || 0);
  if (length > 20000) throw new Error("Слишком большой запрос");

  const body = await request.json();
  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("Некорректные данные");
  }
  return body;
}

async function requireOwner(request, env) {
  if (!env.SESSION_SECRET) {
    throw new Error("Не настроен SESSION_SECRET");
  }
  return verifySession(request, env.SESSION_SECRET);
}

async function getSettings(db) {
  const result = await db.prepare(
    "SELECT key, value FROM site_settings"
  ).all();

  return Object.fromEntries(
    (result.results || []).map(row => [row.key, row.value])
  );
}

async function getPublicData(db) {
  const [settings, services, staff] = await Promise.all([
    getSettings(db),
    db.prepare(
      "SELECT id, title, description, price, image_url, sort_order FROM services WHERE active = 1 ORDER BY sort_order, id"
    ).all(),
    db.prepare(
      "SELECT id, name, position, description, photo_url, sort_order FROM staff WHERE active = 1 ORDER BY sort_order, id"
    ).all()
  ]);

  return {
    settings,
    services: services.results || [],
    staff: staff.results || []
  };
}

async function handleRequest(request, env) {
  if (!env.DB) return json({ error: "База данных DB не подключена" }, 500);
  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
    return json({ error: "Не настроены секреты администратора" }, 500);
  }

  const url = new URL(request.url);
  const route = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;
  const db = env.DB;

  if (route === "/api/login" && method === "POST") {
    if (!validOrigin(request)) return json({ error: "Запрос отклонён" }, 403);

    let body;
    try {
      body = await readBody(request);
    } catch {
      return json({ error: "Некорректный запрос" }, 400);
    }

    if (typeof body.password !== "string" || body.password.length > 200) {
      return json({ error: "Неверный пароль" }, 401);
    }

    if (body.password !== env.ADMIN_PASSWORD) {
      return json({ error: "Неверный пароль" }, 401);
    }

    const token = await createSession(env.SESSION_SECRET);
    return json(
      { success: true },
      200,
      { "Set-Cookie": sessionCookie(token) }
    );
  }

  if (route === "/api/logout" && method === "POST") {
    if (!validOrigin(request)) return json({ error: "Запрос отклонён" }, 403);
    return json(
      { success: true },
      200,
      { "Set-Cookie": clearSessionCookie() }
    );
  }

  if (route === "/api/me" && method === "GET") {
    const authenticated = await requireOwner(request, env);
    return json({ authenticated });
  }

  if (route === "/api/site" && method === "GET") {
    return json(await getPublicData(db));
  }

  if (!route.startsWith("/api/admin/")) {
    return json({ error: "Маршрут не найден" }, 404);
  }

  const authenticated = await requireOwner(request, env);
  if (!authenticated) return json({ error: "Необходим вход" }, 401);

  if (method !== "GET" && !validOrigin(request)) {
    return json({ error: "Запрос отклонён" }, 403);
  }

  // Настройки сайта
  if (route === "/api/admin/settings") {
    const allowedKeys = ["studio_name", "phone", "address", "working_hours"];

    if (method === "GET") {
      return json(await getSettings(db));
    }

    if (method === "PUT") {
      let body;
      try {
        body = await readBody(request);
      } catch {
        return json({ error: "Некорректные данные" }, 400);
      }

      const statements = [];
      for (const key of allowedKeys) {
        if (body[key] !== undefined) {
          const value = safeText(body[key], 300);
          if (value === null) {
            return json({ error: `Некорректное поле: ${key}` }, 400);
          }

          statements.push(
            db.prepare(
              "INSERT INTO site_settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value"
            ).bind(key, value)
          );
        }
      }

      if (statements.length) await db.batch(statements);
      return json({ success: true, settings: await getSettings(db) });
    }
  }

  // Услуги
  if (route === "/api/admin/services") {
    if (method === "GET") {
      const result = await db.prepare(
        "SELECT * FROM services ORDER BY sort_order, id"
      ).all();
      return json(result.results || []);
    }

    if (method === "POST") {
      let body;
      try {
        body = await readBody(request);
      } catch {
        return json({ error: "Некорректные данные" }, 400);
      }

      const title = safeText(body.title, 120);
      const description = safeText(body.description ?? "", 1000);
      const price = safeText(body.price ?? "", 80);
      const image = safeText(body.image_url ?? "", 1000);
      const order = Number(body.sort_order ?? 0);

      if (!title || description === null || price === null || image === null ||
          !Number.isInteger(order) || Math.abs(order) > 10000) {
        return json({ error: "Проверьте поля услуги" }, 400);
      }

      const result = await db.prepare(
        "INSERT INTO services (title, description, price, image_url, sort_order) VALUES (?, ?, ?, ?, ?)"
      ).bind(title, description, price, image, order).run();

      return json({ success: true, id: result.meta.last_row_id }, 201);
    }
  }

  const serviceMatch = route.match(/^\/api\/admin\/services\/(\d+)$/);
  if (serviceMatch) {
    const id = Number(serviceMatch[1]);

    if (method === "PUT") {
      let body;
      try {
        body = await readBody(request);
      } catch {
        return json({ error: "Некорректные данные" }, 400);
      }

      const fields = {
        title: ["title", 120],
        description: ["description", 1000],
        price: ["price", 80],
        image_url: ["image_url", 1000]
      };

      const updates = [];
      for (const [key, [column, max]] of Object.entries(fields)) {
        if (body[key] !== undefined) {
          const value = safeText(body[key], max);
          if (value === null) {
            return json({ error: `Некорректное поле: ${key}` }, 400);
          }
          updates.push({ column, value });
        }
      }

      if (body.active !== undefined) {
        if (![0, 1, false, true].includes(body.active)) {
          return json({ error: "Некорректный статус" }, 400);
        }
        updates.push({ column: "active", value: body.active ? 1 : 0 });
      }

      if (body.sort_order !== undefined) {
        const order = Number(body.sort_order);
        if (!Number.isInteger(order) || Math.abs(order) > 10000) {
          return json({ error: "Некорректный порядок" }, 400);
        }
        updates.push({ column: "sort_order", value: order });
      }

      if (!updates.length) return json({ error: "Нет изменений" }, 400);

      const setClause = updates.map(item => `${item.column} = ?`).join(", ");
      const result = await db.prepare(
        `UPDATE services SET ${setClause} WHERE id = ?`
      ).bind(...updates.map(item => item.value), id).run();

      return json({ success: true, changes: result.meta.changes });
    }

    if (method === "DELETE") {
      const result = await db.prepare(
        "UPDATE services SET active = 0 WHERE id = ?"
      ).bind(id).run();

      return json({ success: true, changes: result.meta.changes });
    }
  }

  // Сотрудники
  if (route === "/api/admin/staff") {
    if (method === "GET") {
      const result = await db.prepare(
        "SELECT * FROM staff ORDER BY sort_order, id"
      ).all();
      return json(result.results || []);
    }

    if (method === "POST") {
      let body;
      try {
        body = await readBody(request);
      } catch {
        return json({ error: "Некорректные данные" }, 400);
      }

      const name = safeText(body.name, 120);
      const position = safeText(body.position ?? "", 120);
      const description = safeText(body.description ?? "", 1000);
      const photo = safeText(body.photo_url ?? "", 1000);
      const order = Number(body.sort_order ?? 0);

      if (!name || position === null || description === null || photo === null ||
          !Number.isInteger(order) || Math.abs(order) > 10000) {
        return json({ error: "Проверьте поля сотрудника" }, 400);
      }

      const result = await db.prepare(
        "INSERT INTO staff (name, position, description, photo_url, sort_order) VALUES (?, ?, ?, ?, ?)"
      ).bind(name, position, description, photo, order).run();

      return json({ success: true, id: result.meta.last_row_id }, 201);
    }
  }

  const staffMatch = route.match(/^\/api\/admin\/staff\/(\d+)$/);
  if (staffMatch) {
    const id = Number(staffMatch[1]);

    if (method === "PUT") {
      let body;
      try {
        body = await readBody(request);
      } catch {
        return json({ error: "Некорректные данные" }, 400);
      }

      const fields = {
        name: ["name", 120],
        position: ["position", 120],
        description: ["description", 1000],
        photo_url: ["photo_url", 1000]
      };

      const updates = [];
      for (const [key, [column, max]] of Object.entries(fields)) {
        if (body[key] !== undefined) {
          const value = safeText(body[key], max);
          if (value === null) {
            return json({ error: `Некорректное поле: ${key}` }, 400);
          }
          updates.push({ column, value });
        }
      }

      if (body.active !== undefined) {
        if (![0, 1, false, true].includes(body.active)) {
          return json({ error: "Некорректный статус" }, 400);
        }
        updates.push({ column: "active", value: body.active ? 1 : 0 });
      }

      if (body.sort_order !== undefined) {
        const order = Number(body.sort_order);
        if (!Number.isInteger(order) || Math.abs(order) > 10000) {
          return json({ error: "Некорректный порядок" }, 400);
        }
        updates.push({ column: "sort_order", value: order });
      }

      if (!updates.length) return json({ error: "Нет изменений" }, 400);

      const setClause = updates.map(item => `${item.column} = ?`).join(", ");
      const result = await db.prepare(
        `UPDATE staff SET ${setClause} WHERE id = ?`
      ).bind(...updates.map(item => item.value), id).run();

      return json({ success: true, changes: result.meta.changes });
    }

    if (method === "DELETE") {
      const result = await db.prepare(
        "UPDATE staff SET active = 0 WHERE id = ?"
      ).bind(id).run();

      return json({ success: true, changes: result.meta.changes });
    }
  }

  // ЗАПИСИ КЛИЕНТОВ
  if (route === "/api/admin/bookings") {
    if (method === "GET") {
      const result = await db.prepare(
        `SELECT id, client_name, phone, service, message, status, created_at
         FROM bookings
         ORDER BY created_at DESC, id DESC`
      ).all();

      return json(result.results || []);
    }
  }

  // Изменение статуса отдельной записи
  const bookingMatch = route.match(/^\/api\/admin\/bookings\/(\d+)$/);
  if (bookingMatch && method === "PUT") {
    const id = Number(bookingMatch[1]);

    let body;
    try {
      body = await readBody(request);
    } catch {
      return json({ error: "Некорректные данные" }, 400);
    }

    if (!BOOKING_STATUSES.includes(body.status)) {
      return json({ error: "Недопустимый статус записи" }, 400);
    }

    const result = await db.prepare(
      "UPDATE bookings SET status = ? WHERE id = ?"
    ).bind(body.status, id).run();

    if (!result.meta.changes) {
      return json({ error: "Запись не найдена" }, 404);
    }

    return json({ success: true, id, status: body.status });
  }

  return json({ error: "Маршрут не найден" }, 404);
}

export async function onRequest(context) {
  try {
    return await handleRequest(context.request, context.env);
  } catch (error) {
    console.error("FINESSSIM API error:", error);
    return json({ error: "Внутренняя ошибка сервера" }, 500);
  }
}
