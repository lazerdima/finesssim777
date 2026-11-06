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

function validAppointment(value) {
  if (typeof value !== "string" ||
      !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)) {
    return false;
  }

  const [datePart, timePart] = value.split("T");
  const [year, month, day] = datePart.split("-").map(Number);
  const [hour, minute] = timePart.split(":").map(Number);
  const date = new Date(year, month - 1, day, hour, minute);

  return date.getFullYear() === year &&
    date.getMonth() === month - 1 &&
    date.getDate() === day &&
    date.getHours() === hour &&
    date.getMinutes() === minute;
}

async function findActiveService(db, id) {
  return db.prepare(
    "SELECT id, title FROM services WHERE id = ? AND active = 1"
  ).bind(id).first();
}

async function findActiveStaff(db, id) {
  return db.prepare(
    "SELECT id, name FROM staff WHERE id = ? AND active = 1"
  ).bind(id).first();
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

  // Вход владельца
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

  // Выход владельца
  if (route === "/api/logout" && method === "POST") {
    if (!validOrigin(request)) return json({ error: "Запрос отклонён" }, 403);
    return json(
      { success: true },
      200,
      { "Set-Cookie": clearSessionCookie() }
    );
  }

  // Проверка авторизации
  if (route === "/api/me" && method === "GET") {
    const authenticated = await requireOwner(request, env);
    return json({ authenticated });
  }

  // Публичные данные сайта
  if (route === "/api/site" && method === "GET") {
    return json(await getPublicData(db));
  }

  if (!route.startsWith("/api/admin/")) {
    return json({ error: "Маршрут не найден" }, 404);
  }

  // Защита административных маршрутов
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

  // Записи клиентов
  if (route === "/api/admin/bookings") {
    if (method === "GET") {
      const result = await db.prepare(
        `SELECT
          b.id,
          b.client_name,
          b.phone,
          b.service,
          b.message,
          b.status,
          b.created_at,
          b.appointment_at,
          b.staff_id,
          b.service_id,
          b.notes,
          b.updated_at,
          s.title AS service_title,
          st.name AS staff_name
        FROM bookings b
        LEFT JOIN services s ON s.id = b.service_id
        LEFT JOIN staff st ON st.id = b.staff_id
        ORDER BY
          CASE WHEN b.appointment_at IS NULL OR b.appointment_at = '' THEN 1 ELSE 0 END,
          b.appointment_at ASC,
          b.created_at DESC,
          b.id DESC`
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

      const clientName = safeText(body.client_name, 120);
      const phone = safeText(body.phone, 40);
      const serviceNameInput = safeText(body.service ?? "", 120);
      const notes = safeText(body.notes ?? body.message ?? "", 2000);
      const appointmentAt = body.appointment_at;
      const status = body.status ?? "new";

      if (!clientName || !phone || serviceNameInput === null ||
          notes === null || !validAppointment(appointmentAt) ||
          !BOOKING_STATUSES.includes(status)) {
        return json({ error: "Проверьте имя, телефон, услугу, дату и время записи" }, 400);
      }

      let serviceId = null;
      let serviceName = serviceNameInput;

      if (body.service_id !== undefined && body.service_id !== null && body.service_id !== "") {
        serviceId = Number(body.service_id);
        if (!Number.isInteger(serviceId) || serviceId <= 0) {
          return json({ error: "Некорректная услуга" }, 400);
        }

        const service = await findActiveService(db, serviceId);
        if (!service) return json({ error: "Выбранная услуга не найдена или отключена" }, 400);
        serviceName = service.title;
      } else if (serviceName) {
        const service = await db.prepare(
          "SELECT id, title FROM services WHERE active = 1 AND LOWER(TRIM(title)) = LOWER(TRIM(?)) LIMIT 1"
        ).bind(serviceName).first();

        if (service) {
          serviceId = service.id;
          serviceName = service.title;
        }
      }

      if (!serviceName) {
        return json({ error: "Выберите услугу" }, 400);
      }

      let staffId = null;
      if (body.staff_id !== undefined && body.staff_id !== null && body.staff_id !== "") {
        staffId = Number(body.staff_id);
        if (!Number.isInteger(staffId) || staffId <= 0) {
          return json({ error: "Некорректный сотрудник" }, 400);
        }

        const staff = await findActiveStaff(db, staffId);
        if (!staff) return json({ error: "Выбранный сотрудник не найден или отключён" }, 400);
      }

      // Защита от двух записей к одному врачу на одно и то же время.
      // Длительность услуги в текущей схеме базы пока не хранится.
      if (staffId !== null) {
        const conflict = await db.prepare(
          `SELECT id FROM bookings
           WHERE staff_id = ?
             AND appointment_at = ?
             AND status != 'cancelled'
           LIMIT 1`
        ).bind(staffId, appointmentAt).first();

        if (conflict) {
          return json({ error: "У этого врача уже есть запись на выбранное время" }, 409);
        }
      }

      const result = await db.prepare(
        `INSERT INTO bookings
          (client_name, phone, service, message, status, appointment_at,
           staff_id, service_id, notes, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)`
      ).bind(
        clientName,
        phone,
        serviceName,
        notes,
        status,
        appointmentAt,
        staffId,
        serviceId,
        notes
      ).run();

      return json({ success: true, id: result.meta.last_row_id }, 201);
    }
  }

  // Изменение статуса и данных отдельной записи
  const bookingMatch = route.match(/^\/api\/admin\/bookings\/(\d+)$/);
  if (bookingMatch && (method === "PUT" || method === "DELETE")) {
    const id = Number(bookingMatch[1]);

    if (method === "DELETE") {
      const result = await db.prepare(
        "UPDATE bookings SET status = 'cancelled', updated_at = CURRENT_TIMESTAMP WHERE id = ?"
      ).bind(id).run();

      if (!result.meta.changes) {
        return json({ error: "Запись не найдена" }, 404);
      }

      return json({ success: true, id, status: "cancelled" });
    }

    let body;
    try {
      body = await readBody(request);
    } catch {
      return json({ error: "Некорректные данные" }, 400);
    }

    const current = await db.prepare(
      `SELECT id, client_name, phone, service, status, appointment_at,
              staff_id, service_id, notes, message
       FROM bookings WHERE id = ?`
    ).bind(id).first();

    if (!current) return json({ error: "Запись не найдена" }, 404);

    const updates = [];
    const addUpdate = (column, value) => updates.push({ column, value });

    if (body.status !== undefined) {
      if (!BOOKING_STATUSES.includes(body.status)) {
        return json({ error: "Недопустимый статус записи" }, 400);
      }
      addUpdate("status", body.status);
    }

    if (body.client_name !== undefined) {
      const value = safeText(body.client_name, 120);
      if (!value) return json({ error: "Проверьте имя клиента" }, 400);
      addUpdate("client_name", value);
    }

    if (body.phone !== undefined) {
      const value = safeText(body.phone, 40);
      if (!value) return json({ error: "Проверьте телефон клиента" }, 400);
      addUpdate("phone", value);
    }

    if (body.notes !== undefined || body.message !== undefined) {
      const value = safeText(body.notes ?? body.message, 2000);
      if (value === null) return json({ error: "Слишком длинное примечание" }, 400);
      addUpdate("notes", value);
      addUpdate("message", value);
    }

    let nextServiceId = current.service_id;
    let nextServiceName = current.service || "";

    if (body.service_id !== undefined) {
      if (body.service_id === null || body.service_id === "") {
        nextServiceId = null;
        if (body.service === undefined) nextServiceName = "";
      } else {
        nextServiceId = Number(body.service_id);
        if (!Number.isInteger(nextServiceId) || nextServiceId <= 0) {
          return json({ error: "Некорректная услуга" }, 400);
        }
        const service = await findActiveService(db, nextServiceId);
        if (!service) return json({ error: "Выбранная услуга не найдена или отключена" }, 400);
        nextServiceName = service.title;
      }
      addUpdate("service_id", nextServiceId);
      addUpdate("service", nextServiceName);
    } else if (body.service !== undefined) {
      const value = safeText(body.service, 120);
      if (!value) return json({ error: "Выберите услугу" }, 400);
      nextServiceName = value;

      const service = await db.prepare(
        "SELECT id, title FROM services WHERE active = 1 AND LOWER(TRIM(title)) = LOWER(TRIM(?)) LIMIT 1"
      ).bind(value).first();

      nextServiceId = service ? service.id : null;
      if (service) nextServiceName = service.title;

      addUpdate("service", nextServiceName);
      addUpdate("service_id", nextServiceId);
    }

    let nextStaffId = current.staff_id;
    if (body.staff_id !== undefined) {
      if (body.staff_id === null || body.staff_id === "") {
        nextStaffId = null;
      } else {
        nextStaffId = Number(body.staff_id);
        if (!Number.isInteger(nextStaffId) || nextStaffId <= 0) {
          return json({ error: "Некорректный сотрудник" }, 400);
        }
        const staff = await findActiveStaff(db, nextStaffId);
        if (!staff) return json({ error: "Выбранный сотрудник не найден или отключён" }, 400);
      }
      addUpdate("staff_id", nextStaffId);
    }

    let nextAppointmentAt = current.appointment_at;
    if (body.appointment_at !== undefined) {
      if (!validAppointment(body.appointment_at)) {
        return json({ error: "Укажите корректные дату и время в формате ГГГГ-ММ-ДДTЧЧ:ММ" }, 400);
      }
      nextAppointmentAt = body.appointment_at;
      addUpdate("appointment_at", nextAppointmentAt);
    }

    if (!updates.length) return json({ error: "Нет изменений" }, 400);

    if (nextStaffId !== null && nextAppointmentAt &&
        (body.staff_id !== undefined || body.appointment_at !== undefined) &&
        (body.status === undefined || body.status !== "cancelled")) {
      const conflict = await db.prepare(
        `SELECT id FROM bookings
         WHERE staff_id = ?
           AND appointment_at = ?
           AND status != 'cancelled'
           AND id != ?
         LIMIT 1`
      ).bind(nextStaffId, nextAppointmentAt, id).first();

      if (conflict) {
        return json({ error: "У этого врача уже есть запись на выбранное время" }, 409);
      }
    }

    const setClause = updates.map(item => `${item.column} = ?`).join(", ");
    const values = updates.map(item => item.value);
    const result = await db.prepare(
      `UPDATE bookings
       SET ${setClause}, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`
    ).bind(...values, id).run();

    if (!result.meta.changes) {
      return json({ error: "Не удалось обновить запись" }, 400);
    }

    return json({ success: true, id, changes: result.meta.changes });
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
