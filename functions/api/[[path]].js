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

const SETTING_KEYS = [
  "studio_name", "phone", "address",
  "telegram", "whatsapp", "instagram", "vk", "map_url",
  "working_hours", "working_days",
  "working_start", "working_end", "slot_interval",
  "hero_eyebrow", "hero_title", "hero_subtitle", "hero_image",
  "intro_eyebrow", "intro_title", "intro_text", "intro_button",
  "services_eyebrow", "services_title", "services_text",
  "about_eyebrow", "about_title", "about_text", "about_image",
  "about_point_1_title", "about_point_1_text",
  "about_point_2_title", "about_point_2_text",
  "about_point_3_title", "about_point_3_text",
  "about_point_4_title", "about_point_4_text",
  "staff_eyebrow", "staff_title", "staff_text",
  "manifesto_title", "manifesto_text",
  "booking_eyebrow", "booking_title", "booking_text",
  "footer_text", "seo_title", "seo_description"
];

const DEFAULT_SCHEDULE = {
  working_days: "1,2,3,4,5",
  working_start: "09:00",
  working_end: "18:00",
  slot_interval: "15"
};

// ================================================
// ОБЩИЕ ФУНКЦИИ
// ================================================

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decodeBase64url(value) {
  const normalized = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const binary = atob(
    normalized + "=".repeat((4 - normalized.length % 4) % 4)
  );

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
  const contentLength = Number(
    request.headers.get("Content-Length") || 0
  );

  if (Number.isFinite(contentLength) && contentLength > 20000) {
    throw new Error("Слишком большой запрос");
  }

  const text = await request.text();

  if (text.length > 20000) {
    throw new Error("Слишком большой запрос");
  }

  let body;

  try {
    body = JSON.parse(text);
  } catch {
    throw new Error("Некорректный JSON");
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    throw new Error("Некорректные данные");
  }

  return body;
}

function validId(value) {
  const id = Number(value);
  return Number.isInteger(id) && id > 0;
}

function validPhone(value) {
  if (typeof value !== "string") return false;

  const digits = value.replace(/\D/g, "");
  return digits.length >= 7 && digits.length <= 15;
}

function validAppointment(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(value)
  ) {
    return false;
  }

  const [datePart, timePart] = value.split("T");
  const [year, month, day] = datePart.split("-").map(Number);
  const [hour, minute] = timePart.split(":").map(Number);

  const date = new Date(year, month - 1, day, hour, minute);

  return (
    date.getFullYear() === year &&
    date.getMonth() === month - 1 &&
    date.getDate() === day &&
    date.getHours() === hour &&
    date.getMinutes() === minute
  );
}

function validBookingDate(value) {
  if (
    typeof value !== "string" ||
    !/^\d{4}-\d{2}-\d{2}$/.test(value)
  ) {
    return false;
  }

  const [year, month, day] = value.split("-").map(Number);
  const date = new Date(Date.UTC(year, month - 1, day));

  return (
    date.getUTCFullYear() === year &&
    date.getUTCMonth() === month - 1 &&
    date.getUTCDate() === day
  );
}

// ================================================
// МОСКОВСКОЕ ВРЕМЯ
// ================================================

function getMoscowDateTime() {
  const parts = new Intl.DateTimeFormat("en-GB", {
    timeZone: "Europe/Moscow",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23"
  }).formatToParts(new Date());

  const values = Object.fromEntries(
    parts.map(part => [part.type, part.value])
  );

  return (
    `${values.year}-${values.month}-${values.day}` +
    `T${values.hour}:${values.minute}`
  );
}

function getMoscowDate() {
  return getMoscowDateTime().slice(0, 10);
}

// ================================================
// TELEGRAM
// ================================================

function escapeTelegramHTML(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

async function sendTelegramBookingNotification(env, booking) {
  const token = env.TELEGRAM_BOT_TOKEN;
  const chatId = env.TELEGRAM_CHAT_ID;

  if (!token || !chatId) {
    console.error("Telegram: не настроены секреты");
    return false;
  }

  const dateParts = booking.appointmentAt.split("T");
  const date = dateParts[0].split("-").reverse().join(".");
  const time = dateParts[1];

  const message = [
    "🦷 <b>НОВАЯ ЗАПИСЬ FINESSSIM</b>",
    "",
    `📋 <b>Заявка №${booking.id}</b>`,
    "",
    `👤 <b>Клиент:</b> ${escapeTelegramHTML(booking.clientName)}`,
    `📞 <b>Телефон:</b> ${escapeTelegramHTML(booking.phone)}`,
    `🦷 <b>Услуга:</b> ${escapeTelegramHTML(booking.service)}`,
    `👨‍⚕️ <b>Врач:</b> ${escapeTelegramHTML(booking.staff)}`,
    `📅 <b>Дата:</b> ${date}`,
    `🕒 <b>Время:</b> ${time}`,
    "",
    `💬 <b>Комментарий:</b> ${escapeTelegramHTML(booking.message || "Нет комментария")}`,
    "",
    "Статус: 🟡 Новая"
  ].join("\n");

  try {
    const response = await fetch(
      `https://api.telegram.org/bot${token}/sendMessage`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          chat_id: chatId,
          text: message,
          parse_mode: "HTML",
          disable_web_page_preview: true
        })
      }
    );

    if (!response.ok) {
      console.error("Telegram notification failed:", response.status);
      return false;
    }

    return true;
  } catch (error) {
    console.error("Telegram notification error:", error);
    return false;
  }
}

// ================================================
// АВТОРИЗАЦИЯ ВЛАДЕЛЬЦА
// ================================================

async function createSession(secret) {
  const payload = base64url(
    encoder.encode(JSON.stringify({
      role: "owner",
      expires: Math.floor(Date.now() / 1000) + SESSION_SECONDS
    }))
  );

  const key = await signingKey(secret);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload)
  );

  return payload + "." + base64url(new Uint8Array(signature));
}

async function verifySession(request, secret) {
  if (!secret) return false;

  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(
    new RegExp("(?:^|;\\s*)" + COOKIE_NAME + "=([^;]+)")
  );

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

    const payload = JSON.parse(
      new TextDecoder().decode(decodeBase64url(parts[0]))
    );

    return (
      payload.role === "owner" &&
      Number.isInteger(payload.expires) &&
      payload.expires > Math.floor(Date.now() / 1000)
    );
  } catch {
    return false;
  }
}

function sessionCookie(value) {
  return (
    `${COOKIE_NAME}=${value}; ` +
    `HttpOnly; Secure; SameSite=Strict; ` +
    `Path=/api; Max-Age=${SESSION_SECONDS}`
  );
}

function clearSessionCookie() {
  return (
    `${COOKIE_NAME}=; ` +
    `HttpOnly; Secure; SameSite=Strict; Path=/api; Max-Age=0`
  );
}

async function requireOwner(request, env) {
  if (!env.SESSION_SECRET) {
    throw new Error("Не настроен SESSION_SECRET");
  }

  return verifySession(request, env.SESSION_SECRET);
}

// ================================================
// РАСПИСАНИЕ
// ================================================

function getWorkingSchedule(settings = {}) {
  const daysRaw = String(
    settings.working_days ?? DEFAULT_SCHEDULE.working_days
  );

  const start = String(
    settings.working_start ?? DEFAULT_SCHEDULE.working_start
  );

  const end = String(
    settings.working_end ?? DEFAULT_SCHEDULE.working_end
  );

  const interval = Number(
    settings.slot_interval ?? DEFAULT_SCHEDULE.slot_interval
  );

  const days = daysRaw.split(",").map(Number);

  const validDays =
    days.length > 0 &&
    days.every(day =>
      Number.isInteger(day) && day >= 0 && day <= 6
    ) &&
    new Set(days).size === days.length;

  const validTime = value =>
    /^\d{2}:\d{2}$/.test(value) &&
    Number(value.slice(0, 2)) <= 23 &&
    Number(value.slice(3, 5)) <= 59;

  if (
    !validDays ||
    !validTime(start) ||
    !validTime(end) ||
    !Number.isInteger(interval) ||
    interval < 5 ||
    interval > 60
  ) {
    return {
      days: [1, 2, 3, 4, 5],
      start: "09:00",
      end: "18:00",
      interval: 15
    };
  }

  const startMinutes =
    Number(start.slice(0, 2)) * 60 +
    Number(start.slice(3, 5));

  const endMinutes =
    Number(end.slice(0, 2)) * 60 +
    Number(end.slice(3, 5));

  if (startMinutes >= endMinutes) {
    return {
      days: [1, 2, 3, 4, 5],
      start: "09:00",
      end: "18:00",
      interval: 15
    };
  }

  return { days, start, end, interval };
}

async function ensureStaffScheduleTable(db) {
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS staff_schedules (
      staff_id INTEGER PRIMARY KEY,
      working_days TEXT NOT NULL,
      working_start TEXT NOT NULL,
      working_end TEXT NOT NULL,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`
  ).run();
}

async function getStaffWorkingSchedule(db, staffId, clinicSettings = {}) {
  const clinicSchedule = getWorkingSchedule(clinicSettings);
  if (!validId(staffId)) return clinicSchedule;
  await ensureStaffScheduleTable(db);
  const personal = await db.prepare(
    "SELECT working_days, working_start, working_end FROM staff_schedules WHERE staff_id = ?"
  ).bind(Number(staffId)).first();
  if (!personal) return clinicSchedule;
  return getWorkingSchedule({
    ...clinicSettings,
    working_days: personal.working_days,
    working_start: personal.working_start,
    working_end: personal.working_end
  });
}

function isWorkingDay(dateString, schedule) {
  if (!validBookingDate(dateString)) return false;

  const [year, month, day] = dateString.split("-").map(Number);

  const weekday = new Date(
    Date.UTC(year, month - 1, day)
  ).getUTCDay();

  return schedule.days.includes(weekday);
}

function isWorkingAppointment(appointmentAt, duration, schedule) {
  if (!validAppointment(appointmentAt)) return false;

  const [date, time] = appointmentAt.split("T");

  if (!isWorkingDay(date, schedule)) return false;

  const [hour, minute] = time.split(":").map(Number);
  const startMinutes = hour * 60 + minute;
  const endMinutes = startMinutes + duration;

  const workingStart =
    Number(schedule.start.slice(0, 2)) * 60 +
    Number(schedule.start.slice(3, 5));

  const workingEnd =
    Number(schedule.end.slice(0, 2)) * 60 +
    Number(schedule.end.slice(3, 5));

  return (
    startMinutes >= workingStart &&
    startMinutes < workingEnd &&
    minute % schedule.interval === 0 &&
    endMinutes <= workingEnd &&
    appointmentAt > getMoscowDateTime()
  );
}

// ================================================
// ФИНАНСЫ: ОБЩИЕ ФУНКЦИИ
// ================================================

// Суммы хранятся в целых рублях.
// Допускаются значения вроде "777", "1 500", "1500 ₽".

function parseRubles(value) {
  if (typeof value === "number") {
    if (
      Number.isSafeInteger(value) &&
      value > 0 &&
      value <= 10000000
    ) {
      return value;
    }

    return null;
  }

  if (typeof value !== "string") return null;

  const cleaned = value
    .trim()
    .replace(/\s/g, "")
    .replace(/₽/g, "")
    .replace(/руб\.?/gi, "");

  if (!/^\d+$/.test(cleaned)) return null;

  const amount = Number(cleaned);

  if (
    !Number.isSafeInteger(amount) ||
    amount <= 0 ||
    amount > 10000000
  ) {
    return null;
  }

  return amount;
}

function validFinancePeriod(from, to) {
  if (!validBookingDate(from) || !validBookingDate(to)) {
    return false;
  }

  return from <= to;
}

async function getBookingPrice(db, booking) {
  let service = null;

  if (booking.service_id) {
    service = await db.prepare(
      "SELECT price FROM services WHERE id = ?"
    ).bind(booking.service_id).first();
  }

  if (!service && booking.service) {
    service = await db.prepare(
      `SELECT price
       FROM services
       WHERE LOWER(TRIM(title)) = LOWER(TRIM(?))
       LIMIT 1`
    ).bind(booking.service).first();
  }

  return parseRubles(service?.price);
}

async function getBookingNetIncome(db, bookingId) {
  const result = await db.prepare(
    `SELECT
       COALESCE(SUM(
         CASE
           WHEN type = 'income' THEN amount
           WHEN type = 'income_reversal' THEN -amount
           ELSE 0
         END
       ), 0) AS net
     FROM finance_transactions
     WHERE booking_id = ?`
  ).bind(bookingId).first();

  return Number(result?.net || 0);
}

async function addBookingIncome(db, booking, amount, eventKey) {
  return db.prepare(
    `INSERT INTO finance_transactions (
       type,
       amount,
       category,
       description,
       booking_id,
       service_title,
       client_name,
       transaction_date,
       event_key
     )
     VALUES (
       'income',
       ?,
       'Услуги клиники',
       ?,
       ?,
       ?,
       ?,
       ?,
       ?
     )`
  ).bind(
    amount,
    `Оплата услуги: ${booking.service || "Стоматологическая услуга"}`,
    booking.id,
    booking.service || "",
    booking.client_name || "",
    getMoscowDate(),
    eventKey
  );
}

async function addIncomeReversal(db, booking, amount, eventKey) {
  return db.prepare(
    `INSERT INTO finance_transactions (
       type,
       amount,
       category,
       description,
       booking_id,
       service_title,
       client_name,
       transaction_date,
       event_key
     )
     VALUES (
       'income_reversal',
       ?,
       'Корректировка дохода',
       ?,
       ?,
       ?,
       ?,
       ?,
       ?
     )`
  ).bind(
    amount,
    `Сторнирование дохода по записи №${booking.id}`,
    booking.id,
    booking.service || "",
    booking.client_name || "",
    getMoscowDate(),
    eventKey
  );
}

// ================================================
// БАЗА ДАННЫХ
// ================================================

async function getSettings(db) {
  const result = await db.prepare(
    "SELECT key, value FROM site_settings"
  ).all();

  return Object.fromEntries(
    (result.results || []).map(row => [row.key, row.value])
  );
}

async function findActiveService(db, id) {
  return db.prepare(
    `SELECT id, title, duration_minutes
     FROM services
     WHERE id = ? AND active = 1`
  ).bind(id).first();
}

async function findActiveStaff(db, id) {
  return db.prepare(
    `SELECT id, name
     FROM staff
     WHERE id = ? AND active = 1`
  ).bind(id).first();
}

async function getServiceDuration(db, serviceId, serviceName) {
  let service = null;

  if (serviceId !== null && serviceId !== undefined) {
    service = await db.prepare(
      "SELECT duration_minutes FROM services WHERE id = ?"
    ).bind(serviceId).first();
  }

  if (!service && serviceName) {
    service = await db.prepare(
      `SELECT duration_minutes
       FROM services
       WHERE LOWER(TRIM(title)) = LOWER(TRIM(?))
       LIMIT 1`
    ).bind(serviceName).first();
  }

  const duration = Number(service?.duration_minutes ?? 60);

  return Number.isInteger(duration) && duration > 0
    ? duration
    : 60;
}

// ================================================
// ПРОВЕРКА ЗАНЯТОСТИ СПЕЦИАЛИСТА
// ================================================

async function hasStaffConflict(
  db,
  staffId,
  appointmentAt,
  durationMinutes,
  excludeId = null
) {
  const conflict = await db.prepare(
    `SELECT b.id
     FROM bookings b
     LEFT JOIN services s ON s.id = b.service_id
     WHERE b.staff_id = ?
       AND b.status != 'cancelled'
       AND b.appointment_at IS NOT NULL
       AND b.appointment_at != ''
       AND datetime(b.appointment_at) <
           datetime(?, '+' || ? || ' minutes')
       AND datetime(
         b.appointment_at,
         '+' || COALESCE(
           s.duration_minutes,
           (
             SELECT legacy_service.duration_minutes
             FROM services legacy_service
             WHERE LOWER(TRIM(legacy_service.title)) =
                   LOWER(TRIM(b.service))
             LIMIT 1
           ),
           60
         ) || ' minutes'
       ) > datetime(?)
       AND (? IS NULL OR b.id != ?)
     LIMIT 1`
  ).bind(
    staffId,
    appointmentAt,
    durationMinutes,
    appointmentAt,
    excludeId,
    excludeId
  ).first();

  return Boolean(conflict);
}

// ================================================
// СВОБОДНОЕ ВРЕМЯ
// ================================================

async function getAvailableSlots(
  db,
  date,
  staffId,
  serviceId,
  settings
) {
  if (
    !validBookingDate(date) ||
    !validId(staffId) ||
    !validId(serviceId)
  ) {
    return [];
  }

  const service = await findActiveService(db, Number(serviceId));
  const staff = await findActiveStaff(db, Number(staffId));
  if (!service || !staff) return [];

  const schedule = await getStaffWorkingSchedule(db, Number(staffId), settings);
  if (!isWorkingDay(date, schedule)) return [];

  const duration = Number(service.duration_minutes) || 60;

  const startMinutes =
    Number(schedule.start.slice(0, 2)) * 60 +
    Number(schedule.start.slice(3, 5));

  const endMinutes =
    Number(schedule.end.slice(0, 2)) * 60 +
    Number(schedule.end.slice(3, 5));

  const slots = [];

  for (
    let minutes = startMinutes;
    minutes + duration <= endMinutes;
    minutes += schedule.interval
  ) {
    const hour = String(Math.floor(minutes / 60)).padStart(2, "0");
    const minute = String(minutes % 60).padStart(2, "0");

    const time = `${hour}:${minute}`;
    const appointmentAt = `${date}T${time}`;

    if (appointmentAt <= getMoscowDateTime()) continue;

    const conflict = await hasStaffConflict(
      db,
      Number(staffId),
      appointmentAt,
      duration
    );

    if (!conflict) slots.push(time);
  }

  return slots;
}

async function getPublicAvailability(request, db) {
  const url = new URL(request.url);

  const date = url.searchParams.get("date");
  const staffId = url.searchParams.get("staff_id");
  const serviceId = url.searchParams.get("service_id");

  if (
    !validBookingDate(date) ||
    !validId(staffId) ||
    !validId(serviceId)
  ) {
    return json(
      { error: "Выберите корректные услугу, врача и дату" },
      400
    );
  }

  const settings = await getSettings(db);
  const schedule = await getStaffWorkingSchedule(db, Number(staffId), settings);

  if (!isWorkingDay(date, schedule)) {
    return json({
      slots: [],
      message: "В этот день специалист не работает"
    });
  }

  const slots = await getAvailableSlots(
    db,
    date,
    staffId,
    serviceId,
    settings
  );

  return json({ slots });
}

// ================================================
// ПУБЛИЧНЫЕ ДАННЫЕ САЙТА
// ================================================

async function getPublicData(db) {
  const [settings, services, staff] = await Promise.all([
    getSettings(db),

    db.prepare(
      `SELECT
        id, title, description, price,
        image_url, duration_minutes, sort_order
       FROM services
       WHERE active = 1
       ORDER BY sort_order, id`
    ).all(),

    db.prepare(
      `SELECT
        id, name, position, description,
        photo_url, sort_order
       FROM staff
       WHERE active = 1
       ORDER BY sort_order, id`
    ).all()
  ]);

  return {
    settings,
    services: services.results || [],
    staff: staff.results || []
  };
}

// ================================================
// ЗАЩИТА ПУБЛИЧНОЙ ФОРМЫ ОТ СПАМА
// ================================================

async function checkPublicBookingRateLimit(request, db, env) {
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS public_booking_rate_limits (
      ip_hash TEXT PRIMARY KEY,
      window_started_at INTEGER NOT NULL,
      hits INTEGER NOT NULL DEFAULT 0
    )`
  ).run();

  const ip = request.headers.get("CF-Connecting-IP") || "unknown";
  const secret = env.SESSION_SECRET || "finesssim-public-booking";
  const digest = await crypto.subtle.digest(
    "SHA-256",
    encoder.encode(secret + ":" + ip)
  );
  const ipHash = Array.from(new Uint8Array(digest))
    .map(byte => byte.toString(16).padStart(2, "0"))
    .join("");

  const now = Math.floor(Date.now() / 1000);
  const windowSeconds = 15 * 60;
  const result = await db.prepare(
    `INSERT INTO public_booking_rate_limits (ip_hash, window_started_at, hits)
     VALUES (?, ?, 1)
     ON CONFLICT(ip_hash) DO UPDATE SET
       hits = CASE
         WHEN window_started_at <= ? THEN 1
         ELSE hits + 1
       END,
       window_started_at = CASE
         WHEN window_started_at <= ? THEN ?
         ELSE window_started_at
       END
     RETURNING hits, window_started_at`
  ).bind(
    ipHash,
    now,
    now - windowSeconds,
    now - windowSeconds,
    now
  ).first();

  if (Number(result?.hits || 0) === 1) {
    await db.prepare(
      "DELETE FROM public_booking_rate_limits WHERE window_started_at < ?"
    ).bind(now - 24 * 60 * 60).run();
  }

  const hits = Number(result?.hits || 0);
  const startedAt = Number(result?.window_started_at || now);
  const retryAfter = Math.max(1, startedAt + windowSeconds - now);

  return {
    limited: hits > 12,
    retryAfter
  };
}

// ================================================
// ПУБЛИЧНАЯ ЗАПИСЬ
// ================================================

async function createPublicBooking(request, db, env) {
  if (!validOrigin(request)) {
    return json({ error: "Запрос отклонён" }, 403);
  }

  const rateLimit = await checkPublicBookingRateLimit(request, db, env);
  if (rateLimit.limited) {
    return json(
      { error: "Слишком много попыток записи. Попробуйте немного позже." },
      429,
      { "Retry-After": String(rateLimit.retryAfter) }
    );
  }

  let body;

  try {
    body = await readBody(request);
  } catch {
    return json({ error: "Некорректные данные формы" }, 400);
  }

  const website = safeText(body.website ?? "", 200);

  if (website === null) {
    return json({ error: "Некорректные данные" }, 400);
  }

  if (website !== "") {
    return json({
      success: true,
      message: "Заявка успешно отправлена"
    });
  }

  const clientName = safeText(
    body.client_name ?? body.name ?? "",
    120
  );

  const phone = safeText(body.phone ?? "", 40);
  const message = safeText(body.message ?? "", 2000);

  if (
    !clientName ||
    clientName.length < 2 ||
    !phone ||
    !validPhone(phone) ||
    message === null ||
    !validId(body.service_id) ||
    !validId(body.staff_id) ||
    !validAppointment(body.appointment_at)
  ) {
    return json(
      {
        error: "Заполните имя, телефон, услугу, врача, дату и время"
      },
      400
    );
  }

  const serviceId = Number(body.service_id);
  const staffId = Number(body.staff_id);
  const appointmentAt = body.appointment_at;

  const service = await findActiveService(db, serviceId);
  const staff = await findActiveStaff(db, staffId);

  if (!service) {
    return json(
      {
        error: "Выбранная услуга больше недоступна. Обновите страницу."
      },
      400
    );
  }

  if (!staff) {
    return json(
      {
        error: "Выбранный специалист больше недоступен. Обновите страницу."
      },
      400
    );
  }

  const duration = Number(service.duration_minutes) || 60;
  const settings = await getSettings(db);
  const schedule = await getStaffWorkingSchedule(db, staffId, settings);

  if (!isWorkingAppointment(appointmentAt, duration, schedule)) {
    return json(
      {
        error: "Выбранное время находится вне рабочего расписания или уже прошло"
      },
      400
    );
  }

  const result = await db.prepare(
    `INSERT INTO bookings (
      client_name, phone, service, message, status,
      appointment_at, staff_id, service_id, notes, updated_at
    )
    SELECT
      ?, ?, ?, ?, 'new', ?, ?, ?, ?, CURRENT_TIMESTAMP
    WHERE NOT EXISTS (
      SELECT 1
      FROM bookings b
      LEFT JOIN services s ON s.id = b.service_id
      WHERE b.staff_id = ?
        AND b.status != 'cancelled'
        AND b.appointment_at IS NOT NULL
        AND b.appointment_at != ''
        AND datetime(b.appointment_at) <
            datetime(?, '+' || ? || ' minutes')
        AND datetime(
          b.appointment_at,
          '+' || COALESCE(
            s.duration_minutes,
            (
              SELECT legacy_service.duration_minutes
              FROM services legacy_service
              WHERE LOWER(TRIM(legacy_service.title)) =
                    LOWER(TRIM(b.service))
              LIMIT 1
            ),
            60
          ) || ' minutes'
        ) > datetime(?)
    )`
  ).bind(
    clientName,
    phone,
    service.title,
    message,
    appointmentAt,
    staffId,
    serviceId,
    message,
    staffId,
    appointmentAt,
    duration,
    appointmentAt
  ).run();

  if (!result.meta.changes) {
    return json(
      {
        error: "Это время уже занято. Обновите список свободного времени и выберите другой слот."
      },
      409
    );
  }

  await sendTelegramBookingNotification(env, {
    id: result.meta.last_row_id,
    clientName,
    phone,
    service: service.title,
    staff: staff.name,
    appointmentAt,
    message
  });

  return json(
    {
      success: true,
      message: "Заявка успешно отправлена! Мы свяжемся с вами для подтверждения.",
      id: result.meta.last_row_id
    },
    201
  );
}

// ================================================
// НАСТРОЙКИ САЙТА
// ================================================

function validateScheduleInput(body, currentSettings) {
  const candidate = {
    ...currentSettings,
    ...body
  };

  const daysRaw = String(
    candidate.working_days ?? DEFAULT_SCHEDULE.working_days
  );

  const days = daysRaw.split(",").map(Number);

  if (
    !days.length ||
    days.some(day =>
      !Number.isInteger(day) || day < 0 || day > 6
    ) ||
    new Set(days).size !== days.length
  ) {
    return "Рабочие дни должны быть числами от 0 до 6 через запятую";
  }

  const start = String(
    candidate.working_start ?? DEFAULT_SCHEDULE.working_start
  );

  const end = String(
    candidate.working_end ?? DEFAULT_SCHEDULE.working_end
  );

  const validTime = value =>
    /^\d{2}:\d{2}$/.test(value) &&
    Number(value.slice(0, 2)) <= 23 &&
    Number(value.slice(3, 5)) <= 59;

  if (!validTime(start) || !validTime(end)) {
    return "Укажите время в формате ЧЧ:ММ";
  }

  const startMinutes =
    Number(start.slice(0, 2)) * 60 +
    Number(start.slice(3, 5));

  const endMinutes =
    Number(end.slice(0, 2)) * 60 +
    Number(end.slice(3, 5));

  if (startMinutes >= endMinutes) {
    return "Время окончания должно быть позже времени начала";
  }

  const interval = Number(candidate.slot_interval);

  if (
    !Number.isInteger(interval) ||
    interval < 5 ||
    interval > 60
  ) {
    return "Интервал записи должен быть от 5 до 60 минут";
  }

  return null;
}

async function handleSettings(request, db, method) {
  if (method === "GET") {
    return json(await getSettings(db));
  }

  if (method !== "PUT") {
    return json({ error: "Метод не поддерживается" }, 405);
  }

  let body;

  try {
    body = await readBody(request);
  } catch {
    return json({ error: "Некорректные данные" }, 400);
  }

  const unknownKeys = Object.keys(body).filter(
    key => !SETTING_KEYS.includes(key)
  );

  if (unknownKeys.length) {
    return json(
      { error: `Неизвестные настройки: ${unknownKeys.join(", ")}` },
      400
    );
  }

  const currentSettings = await getSettings(db);

  const scheduleError = validateScheduleInput(
    body,
    currentSettings
  );

  const scheduleFields = [
    "working_days",
    "working_start",
    "working_end",
    "slot_interval"
  ];

  const changesSchedule = scheduleFields.some(
    key => body[key] !== undefined
  );

  if (changesSchedule && scheduleError) {
    return json({ error: scheduleError }, 400);
  }

  const statements = [];

  for (const key of SETTING_KEYS) {
    if (body[key] === undefined) continue;

    const maxLength = [
      "hero_image",
      "about_image",
      "map_url"
    ].includes(key) ? 2000 : 5000;

    const value = safeText(body[key], maxLength);

    if (value === null) {
      return json(
        { error: `Некорректное поле: ${key}` },
        400
      );
    }

    statements.push(
      db.prepare(
        `INSERT INTO site_settings (key, value)
         VALUES (?, ?)
         ON CONFLICT(key)
         DO UPDATE SET value = excluded.value`
      ).bind(key, value)
    );
  }

  if (statements.length) {
    await db.batch(statements);
    await logAdminAction(db, "Изменил настройки сайта", "site_settings", null, body);
  }

  return json({
    success: true,
    settings: await getSettings(db)
  });
}

// ================================================
// УПРАВЛЕНИЕ УСЛУГАМИ
// ================================================

async function handleServices(request, db, route, method) {
  if (route === "/api/admin/services") {
    if (method === "GET") {
      const result = await db.prepare(
        "SELECT * FROM services ORDER BY sort_order, id"
      ).all();

      return json(result.results || []);
    }

    if (method !== "POST") {
      return json({ error: "Метод не поддерживается" }, 405);
    }

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
    const duration = Number(body.duration_minutes ?? 60);

    if (
      !title ||
      description === null ||
      price === null ||
      image === null ||
      !Number.isInteger(order) ||
      Math.abs(order) > 10000 ||
      !Number.isInteger(duration) ||
      duration < 5 ||
      duration > 600
    ) {
      return json({ error: "Проверьте поля услуги" }, 400);
    }

    const result = await db.prepare(
      `INSERT INTO services (
        title, description, price, image_url,
        duration_minutes, sort_order
      ) VALUES (?, ?, ?, ?, ?, ?)`
    ).bind(
      title, description, price, image, duration, order
    ).run();

    await logAdminAction(db, "Добавил услугу", "service", result.meta.last_row_id, {
      title, description, price, image_url: image, duration_minutes: duration, sort_order: order
    });
    return json({ success: true, id: result.meta.last_row_id }, 201);
  }

  const match = route.match(
    /^\/api\/admin\/services\/(\d+)$/
  );

  if (!match) return null;

  const id = Number(match[1]);

  if (method === "DELETE") {
    const result = await db.prepare(
      "UPDATE services SET active = 0 WHERE id = ?"
    ).bind(id).run();

    if (!result.meta.changes) {
      return json({ error: "Услуга не найдена" }, 404);
    }

    await logAdminAction(db, "Скрыл услугу", "service", id, { active: 0 });
    return json({ success: true, changes: result.meta.changes });
  }

  if (method !== "PUT") {
    return json({ error: "Метод не поддерживается" }, 405);
  }

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
    if (body[key] === undefined) continue;

    const value = safeText(body[key], max);

    if (value === null) {
      return json({ error: `Некорректное поле: ${key}` }, 400);
    }

    updates.push({ column, value });
  }

  if (body.duration_minutes !== undefined) {
    const duration = Number(body.duration_minutes);

    if (
      !Number.isInteger(duration) ||
      duration < 5 ||
      duration > 600
    ) {
      return json(
        { error: "Некорректная продолжительность услуги" },
        400
      );
    }

    updates.push({
      column: "duration_minutes",
      value: duration
    });
  }

  if (body.active !== undefined) {
    if (![0, 1, false, true].includes(body.active)) {
      return json({ error: "Некорректный статус" }, 400);
    }

    updates.push({
      column: "active",
      value: body.active ? 1 : 0
    });
  }

  if (body.sort_order !== undefined) {
    const order = Number(body.sort_order);

    if (!Number.isInteger(order) || Math.abs(order) > 10000) {
      return json({ error: "Некорректный порядок" }, 400);
    }

    updates.push({ column: "sort_order", value: order });
  }

  if (!updates.length) {
    return json({ error: "Нет изменений" }, 400);
  }

  const setClause = updates
    .map(item => `${item.column} = ?`)
    .join(", ");

  const result = await db.prepare(
    `UPDATE services SET ${setClause} WHERE id = ?`
  ).bind(
    ...updates.map(item => item.value),
    id
  ).run();

  if (!result.meta.changes) {
    return json({ error: "Услуга не найдена" }, 404);
  }

  await logAdminAction(db, "Изменил услугу", "service", id, body);
  return json({ success: true, changes: result.meta.changes });
}

// ================================================
// УПРАВЛЕНИЕ КОМАНДОЙ
// ================================================

async function handleStaff(request, db, route, method) {
  if (route === "/api/admin/staff") {
    if (method === "GET") {
      await ensureStaffScheduleTable(db);
      const [result, settings, schedules] = await Promise.all([
        db.prepare("SELECT * FROM staff ORDER BY sort_order, id").all(),
        getSettings(db),
        db.prepare("SELECT staff_id, working_days, working_start, working_end FROM staff_schedules").all()
      ]);
      const scheduleMap = new Map((schedules.results || []).map(item => [Number(item.staff_id), item]));
      return json((result.results || []).map(person => {
        const schedule = scheduleMap.get(Number(person.id));
        return {
          ...person,
          working_days: schedule?.working_days ?? settings.working_days ?? DEFAULT_SCHEDULE.working_days,
          working_start: schedule?.working_start ?? settings.working_start ?? DEFAULT_SCHEDULE.working_start,
          working_end: schedule?.working_end ?? settings.working_end ?? DEFAULT_SCHEDULE.working_end
        };
      }));
    }

    if (method !== "POST") {
      return json({ error: "Метод не поддерживается" }, 405);
    }

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

    if (
      !name ||
      position === null ||
      description === null ||
      photo === null ||
      !Number.isInteger(order) ||
      Math.abs(order) > 10000
    ) {
      return json({ error: "Проверьте поля сотрудника" }, 400);
    }

    const result = await db.prepare(
      `INSERT INTO staff (
        name, position, description, photo_url, sort_order
      ) VALUES (?, ?, ?, ?, ?)`
    ).bind(name, position, description, photo, order).run();

    await logAdminAction(db, "Добавил сотрудника", "staff", result.meta.last_row_id, {
      name, position, description, photo_url: photo, sort_order: order
    });
    return json({ success: true, id: result.meta.last_row_id }, 201);
  }

  const match = route.match(
    /^\/api\/admin\/staff\/(\d+)$/
  );

  if (!match) return null;

  const id = Number(match[1]);

  if (method === "DELETE") {
    const result = await db.prepare(
      "UPDATE staff SET active = 0 WHERE id = ?"
    ).bind(id).run();

    if (!result.meta.changes) {
      return json({ error: "Сотрудник не найден" }, 404);
    }

    await logAdminAction(db, "Скрыл сотрудника", "staff", id, { active: 0 });
    return json({ success: true, changes: result.meta.changes });
  }

  if (method !== "PUT") {
    return json({ error: "Метод не поддерживается" }, 405);
  }

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
    if (body[key] === undefined) continue;

    const value = safeText(body[key], max);

    if (value === null) {
      return json({ error: `Некорректное поле: ${key}` }, 400);
    }

    updates.push({ column, value });
  }

  if (body.active !== undefined) {
    if (![0, 1, false, true].includes(body.active)) {
      return json({ error: "Некорректный статус" }, 400);
    }

    updates.push({
      column: "active",
      value: body.active ? 1 : 0
    });
  }

  if (body.sort_order !== undefined) {
    const order = Number(body.sort_order);

    if (!Number.isInteger(order) || Math.abs(order) > 10000) {
      return json({ error: "Некорректный порядок" }, 400);
    }

    updates.push({ column: "sort_order", value: order });
  }

  const scheduleFields = ["working_days", "working_start", "working_end"];
  const scheduleChanged = scheduleFields.some(key => body[key] !== undefined);
  let scheduleValues = null;

  if (scheduleChanged) {
    await ensureStaffScheduleTable(db);
    const [currentSettings, currentSchedule] = await Promise.all([
      getSettings(db),
      db.prepare(
        "SELECT working_days, working_start, working_end FROM staff_schedules WHERE staff_id = ?"
      ).bind(id).first()
    ]);
    scheduleValues = {
      working_days: body.working_days ?? currentSchedule?.working_days ?? currentSettings.working_days ?? DEFAULT_SCHEDULE.working_days,
      working_start: body.working_start ?? currentSchedule?.working_start ?? currentSettings.working_start ?? DEFAULT_SCHEDULE.working_start,
      working_end: body.working_end ?? currentSchedule?.working_end ?? currentSettings.working_end ?? DEFAULT_SCHEDULE.working_end,
      slot_interval: currentSettings.slot_interval ?? DEFAULT_SCHEDULE.slot_interval
    };
    const scheduleError = validateScheduleInput(scheduleValues, currentSettings);
    if (scheduleError) return json({ error: scheduleError }, 400);
  }

  if (!updates.length && !scheduleChanged) {
    return json({ error: "Нет изменений" }, 400);
  }

  let changes = 0;
  if (updates.length) {
    const setClause = updates.map(item => `${item.column} = ?`).join(", ");
    const result = await db.prepare(
      `UPDATE staff SET ${setClause} WHERE id = ?`
    ).bind(...updates.map(item => item.value), id).run();
    changes = result.meta.changes;
  } else {
    const exists = await db.prepare("SELECT id FROM staff WHERE id = ?").bind(id).first();
    changes = exists ? 1 : 0;
  }

  if (!changes) return json({ error: "Сотрудник не найден" }, 404);

  if (scheduleChanged) {
    await db.prepare(
      `INSERT INTO staff_schedules (staff_id, working_days, working_start, working_end, updated_at)
       VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)
       ON CONFLICT(staff_id) DO UPDATE SET
         working_days = excluded.working_days,
         working_start = excluded.working_start,
         working_end = excluded.working_end,
         updated_at = CURRENT_TIMESTAMP`
    ).bind(id, scheduleValues.working_days, scheduleValues.working_start, scheduleValues.working_end).run();
  }

  await logAdminAction(db, "Изменил данные сотрудника", "staff", id, body);
  return json({ success: true, changes });
}

// ================================================
// ПОЛУЧЕНИЕ ЗАПИСЕЙ
// ================================================

async function getBookings(db) {
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
      s.duration_minutes AS duration_minutes,
      st.name AS staff_name
    FROM bookings b
    LEFT JOIN services s ON s.id = b.service_id
    LEFT JOIN staff st ON st.id = b.staff_id
    ORDER BY
      CASE
        WHEN b.appointment_at IS NULL OR b.appointment_at = ''
        THEN 1 ELSE 0
      END,
      b.appointment_at ASC,
      b.created_at DESC,
      b.id DESC`
  ).all();

  return result.results || [];
}

// ================================================
// СОЗДАНИЕ ЗАПИСИ ВЛАДЕЛЬЦЕМ
// ================================================

async function createAdminBooking(request, db, env) {
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

  if (
    !clientName ||
    !phone ||
    !validPhone(phone) ||
    serviceNameInput === null ||
    notes === null ||
    !validAppointment(appointmentAt) ||
    !BOOKING_STATUSES.includes(status)
  ) {
    return json(
      {
        error: "Проверьте имя, телефон, услугу, дату и время записи"
      },
      400
    );
  }

  let serviceId = null;
  let serviceName = serviceNameInput;

  if (
    body.service_id !== undefined &&
    body.service_id !== null &&
    body.service_id !== ""
  ) {
    if (!validId(body.service_id)) {
      return json({ error: "Некорректная услуга" }, 400);
    }

    serviceId = Number(body.service_id);

    const service = await findActiveService(db, serviceId);

    if (!service) {
      return json(
        { error: "Выбранная услуга не найдена или отключена" },
        400
      );
    }

    serviceName = service.title;

  } else if (serviceName) {
    const service = await db.prepare(
      `SELECT id, title
       FROM services
       WHERE active = 1
         AND LOWER(TRIM(title)) = LOWER(TRIM(?))
       LIMIT 1`
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

  if (
    body.staff_id !== undefined &&
    body.staff_id !== null &&
    body.staff_id !== ""
  ) {
    if (!validId(body.staff_id)) {
      return json({ error: "Некорректный сотрудник" }, 400);
    }

    staffId = Number(body.staff_id);

    const staff = await findActiveStaff(db, staffId);

    if (!staff) {
      return json(
        { error: "Выбранный сотрудник не найден или отключён" },
        400
      );
    }
  }

  const duration = await getServiceDuration(db, serviceId, serviceName);
  const settings = await getSettings(db);
  const schedule = await getStaffWorkingSchedule(db, staffId, settings);

  if (status !== "cancelled" && status !== "completed" && !isWorkingAppointment(appointmentAt, duration, schedule)) {
    return json({ error: "Время записи находится вне рабочего графика специалиста или уже прошло" }, 400);
  }

  if (staffId !== null && status !== "cancelled" && status !== "completed") {
    const conflict = await hasStaffConflict(db, staffId, appointmentAt, duration);
    if (conflict) {
      return json(
        { error: "В это время специалист занят другой записью. Выберите другое время." },
        409
      );
    }
  }

  let incomeAmount = null;

  if (status === "completed") {
    incomeAmount = body.income_amount !== undefined
      ? parseRubles(body.income_amount)
      : null;

    if (incomeAmount === null) {
      return json(
        {
          error: "Для создания завершённой записи укажите income_amount — сумму оплаты в рублях."
        },
        400
      );
    }
  }

  const result = await db.prepare(
    `INSERT INTO bookings (
      client_name, phone, service, message, status,
      appointment_at, staff_id, service_id, notes, updated_at
    )
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

  const bookingId = result.meta.last_row_id;

  if (status === "completed") {
    const eventKey = `booking:${bookingId}:initial-income:${crypto.randomUUID()}`;

    await db.prepare(
      `INSERT INTO finance_transactions (
        type, amount, category, description,
        booking_id, service_title, client_name,
        transaction_date, event_key
      )
      VALUES (
        'income', ?, 'Услуги клиники', ?,
        ?, ?, ?, ?, ?
      )`
    ).bind(
      incomeAmount,
      `Оплата услуги: ${serviceName}`,
      bookingId,
      serviceName,
      clientName,
      getMoscowDate(),
      eventKey
    ).run();
  }

  let staffName = "Не назначен";
  if (staffId !== null) {
    const staff = await db.prepare("SELECT name FROM staff WHERE id = ?").bind(staffId).first();
    if (staff?.name) staffName = staff.name;
  }

  await sendTelegramBookingNotification(env, {
    id: bookingId, clientName, phone, service: serviceName,
    staff: staffName, appointmentAt, message: notes
  });
  await logAdminAction(db, "Создал запись", "booking", bookingId, {
    client_name: clientName, phone, service: serviceName,
    appointment_at: appointmentAt, staff_id: staffId, status
  });

  return json({ success: true, id: bookingId }, 201);
}

// ================================================
// ОБНОВЛЕНИЕ ЗАПИСИ И ФИНАНСОВЫЕ СОБЫТИЯ
// ================================================

async function updateBooking(request, db, id) {
  let body;

  try {
    body = await readBody(request);
  } catch {
    return json({ error: "Некорректные данные" }, 400);
  }

  const current = await db.prepare(
    `SELECT
      id, client_name, phone, service, status,
      appointment_at, staff_id, service_id, notes, message
     FROM bookings
     WHERE id = ?`
  ).bind(id).first();

  if (!current) {
    return json({ error: "Запись не найдена" }, 404);
  }

  const updates = [];
  const addUpdate = (column, value) => {
    updates.push({ column, value });
  };

  let nextStatus = current.status;

  if (body.status !== undefined) {
    if (!BOOKING_STATUSES.includes(body.status)) {
      return json({ error: "Недопустимый статус записи" }, 400);
    }

    nextStatus = body.status;
    addUpdate("status", body.status);
  }

  if (body.client_name !== undefined) {
    const value = safeText(body.client_name, 120);

    if (!value) {
      return json({ error: "Проверьте имя клиента" }, 400);
    }

    addUpdate("client_name", value);
  }

  if (body.phone !== undefined) {
    const value = safeText(body.phone, 40);

    if (!value || !validPhone(value)) {
      return json({ error: "Проверьте телефон клиента" }, 400);
    }

    addUpdate("phone", value);
  }

  if (body.notes !== undefined || body.message !== undefined) {
    const value = safeText(body.notes ?? body.message, 2000);

    if (value === null) {
      return json({ error: "Слишком длинное примечание" }, 400);
    }

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
      if (!validId(body.service_id)) {
        return json({ error: "Некорректная услуга" }, 400);
      }

      nextServiceId = Number(body.service_id);

      const service = await findActiveService(db, nextServiceId);

      if (!service) {
        return json(
          { error: "Выбранная услуга не найдена или отключена" },
          400
        );
      }

      nextServiceName = service.title;
    }

    addUpdate("service_id", nextServiceId);
    addUpdate("service", nextServiceName);

  } else if (body.service !== undefined) {
    const value = safeText(body.service, 120);

    if (!value) {
      return json({ error: "Выберите услугу" }, 400);
    }

    nextServiceName = value;

    const service = await db.prepare(
      `SELECT id, title
       FROM services
       WHERE active = 1
         AND LOWER(TRIM(title)) = LOWER(TRIM(?))
       LIMIT 1`
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
      if (!validId(body.staff_id)) {
        return json({ error: "Некорректный сотрудник" }, 400);
      }

      nextStaffId = Number(body.staff_id);

      const staff = await findActiveStaff(db, nextStaffId);

      if (!staff) {
        return json(
          { error: "Выбранный сотрудник не найден или отключён" },
          400
        );
      }
    }

    addUpdate("staff_id", nextStaffId);
  }

  let nextAppointmentAt = current.appointment_at;

  if (body.appointment_at !== undefined) {
    if (!validAppointment(body.appointment_at)) {
      return json(
        { error: "Укажите корректную дату и время" },
        400
      );
    }

    nextAppointmentAt = body.appointment_at;
    addUpdate("appointment_at", nextAppointmentAt);
  }

  if (!updates.length) {
    return json({ error: "Нет изменений" }, 400);
  }

  const appointmentChanged = (
    body.staff_id !== undefined || body.appointment_at !== undefined ||
    ((body.service_id !== undefined || body.service !== undefined) && nextStatus !== "completed") ||
    (body.status !== undefined && nextStatus !== "completed" && nextStatus !== "cancelled")
  );

  if (appointmentChanged && nextAppointmentAt && nextStatus !== "cancelled") {
    const duration = await getServiceDuration(db, nextServiceId, nextServiceName);
    const settings = await getSettings(db);
    const schedule = await getStaffWorkingSchedule(db, nextStaffId, settings);

    if (!isWorkingAppointment(nextAppointmentAt, duration, schedule)) {
      return json({ error: "Время записи находится вне рабочего графика специалиста или уже прошло" }, 400);
    }

    if (nextStaffId !== null) {
      const conflict = await hasStaffConflict(db, nextStaffId, nextAppointmentAt, duration, id);
      if (conflict) {
        return json(
          { error: "В это время специалист занят другой записью. Выберите другое время." },
          409
        );
      }
    }
  }

  const statusChanged = nextStatus !== current.status;

  // Если запись переводится в завершённые — определяем сумму.
  let incomeAmount = null;

  if (statusChanged && nextStatus === "completed") {
    if (body.income_amount !== undefined) {
      incomeAmount = parseRubles(body.income_amount);
    } else {
      incomeAmount = await getBookingPrice(db, {
        service_id: nextServiceId,
        service: nextServiceName
      });
    }

    if (incomeAmount === null) {
      return json(
        {
          error: "У этой услуги не указана корректная цена. Введите сумму оплаты в поле income_amount."
        },
        400
      );
    }
  }

  // Если запись была завершена, но статус меняется —
  // рассчитываем сумму, которую нужно сторнировать.
  let reversalAmount = 0;

  if (statusChanged && current.status === "completed" && nextStatus !== "completed") {
    reversalAmount = await getBookingNetIncome(db, id);
  }

  const setClause = updates
    .map(item => `${item.column} = ?`)
    .join(", ");

  // Уникальная метка защищает от повторной обработки одного изменения.
  const transitionMarker = `${new Date().toISOString()}-${crypto.randomUUID()}`;

  const updateSql = statusChanged
    ? `UPDATE bookings
       SET ${setClause}, updated_at = ?
       WHERE id = ? AND status = ?`
    : `UPDATE bookings
       SET ${setClause}, updated_at = CURRENT_TIMESTAMP
       WHERE id = ?`;

  const updateStatement = statusChanged
    ? db.prepare(updateSql).bind(
        ...updates.map(item => item.value),
        transitionMarker,
        id,
        current.status
      )
    : db.prepare(updateSql).bind(
        ...updates.map(item => item.value),
        id
      );

  if (!statusChanged) {
    const result = await updateStatement.run();

    if (!result.meta.changes) {
      return json({ error: "Не удалось обновить запись" }, 400);
    }

    await logAdminAction(db, "Изменил запись", "booking", id, {
      before: { status: current.status, appointment_at: current.appointment_at, staff_id: current.staff_id, service: current.service },
      after: { status: nextStatus, appointment_at: nextAppointmentAt, staff_id: nextStaffId, service: nextServiceName }
    });
    return json({ success: true, id, changes: result.meta.changes });
  }

  const statements = [updateStatement];

  if (nextStatus === "completed") {
    const eventKey = `booking:${id}:income:${transitionMarker}`;

    statements.push(
      db.prepare(
        `INSERT INTO finance_transactions (
          type, amount, category, description,
          booking_id, service_title, client_name,
          transaction_date, event_key
        )
        SELECT
          'income', ?, 'Услуги клиники', ?,
          ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1
          FROM bookings
          WHERE id = ? AND status = 'completed' AND updated_at = ?
        )`
      ).bind(
        incomeAmount,
        `Оплата услуги: ${nextServiceName || "Стоматологическая услуга"}`,
        id,
        nextServiceName,
        current.client_name,
        getMoscowDate(),
        eventKey,
        id,
        transitionMarker
      )
    );
  }

  if (
    current.status === "completed" &&
    nextStatus !== "completed" &&
    reversalAmount > 0
  ) {
    const eventKey = `booking:${id}:reversal:${transitionMarker}`;

    statements.push(
      db.prepare(
        `INSERT INTO finance_transactions (
          type, amount, category, description,
          booking_id, service_title, client_name,
          transaction_date, event_key
        )
        SELECT
          'income_reversal', ?, 'Корректировка дохода', ?,
          ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1
          FROM bookings
          WHERE id = ? AND status = ? AND updated_at = ?
        )`
      ).bind(
        reversalAmount,
        `Сторнирование дохода по записи №${id}`,
        id,
        current.service || "",
        current.client_name,
        getMoscowDate(),
        eventKey,
        id,
        nextStatus,
        transitionMarker
      )
    );
  }

  const results = await db.batch(statements);
  const updateResult = results[0];

  if (!updateResult?.meta?.changes) {
    return json(
      {
        error: "Запись уже была изменена. Обновите страницу и повторите действие."
      },
      409
    );
  }

  await logAdminAction(db, nextStatus !== current.status ? "Изменил статус записи" : "Изменил запись", "booking", id, {
    before: { status: current.status, appointment_at: current.appointment_at, staff_id: current.staff_id, service: current.service },
    after: { status: nextStatus, appointment_at: nextAppointmentAt, staff_id: nextStaffId, service: nextServiceName }
  });
  return json({ success: true, id, changes: updateResult.meta.changes });
}

// ================================================
// ФИНАНСЫ: ПОЛУЧЕНИЕ СВОДКИ И ИСТОРИИ
// ================================================

async function getFinance(request, db) {
  const url = new URL(request.url);

  const defaultTo = getMoscowDate();
  const defaultFrom = `${defaultTo.slice(0, 7)}-01`;

  const from = url.searchParams.get("from") || defaultFrom;
  const to = url.searchParams.get("to") || defaultTo;

  if (!validFinancePeriod(from, to)) {
    return json(
      { error: "Укажите корректный период в формате ГГГГ-ММ-ДД" },
      400
    );
  }

  const summary = await db.prepare(
    `SELECT
       COALESCE(SUM(
         CASE
           WHEN type = 'income' THEN amount
           WHEN type = 'income_reversal' THEN -amount
           ELSE 0
         END
       ), 0) AS income,

       COALESCE(SUM(
         CASE
           WHEN type = 'expense' THEN amount
           ELSE 0
         END
       ), 0) AS expenses

     FROM finance_transactions
     WHERE transaction_date >= ?
       AND transaction_date <= ?`
  ).bind(from, to).first();

  const transactions = await db.prepare(
    `SELECT
       id,
       type,
       amount,
       category,
       description,
       booking_id,
       service_title,
       client_name,
       transaction_date,
       created_at
     FROM finance_transactions
     WHERE transaction_date >= ?
       AND transaction_date <= ?
     ORDER BY transaction_date DESC, id DESC`
  ).bind(from, to).all();

  const income = Number(summary?.income || 0);
  const expenses = Number(summary?.expenses || 0);

  return json({
    from,
    to,
    summary: {
      income,
      expenses,
      profit: income - expenses
    },
    transactions: transactions.results || []
  });
}

// ================================================
// ФИНАНСЫ: ДОБАВЛЕНИЕ РАСХОДА
// ================================================

async function createFinanceExpense(request, db) {
  let body;

  try {
    body = await readBody(request);
  } catch {
    return json({ error: "Некорректные данные" }, 400);
  }

  const amount = parseRubles(body.amount);
  const category = safeText(body.category, 100);
  const description = safeText(body.description ?? "", 1000);
  const date = body.transaction_date || getMoscowDate();

  if (!amount) {
    return json(
      { error: "Укажите корректную сумму расхода в рублях" },
      400
    );
  }

  if (!category || category.length < 2) {
    return json(
      { error: "Укажите категорию расхода" },
      400
    );
  }

  if (description === null) {
    return json(
      { error: "Комментарий слишком длинный" },
      400
    );
  }

  if (!validBookingDate(date)) {
    return json(
      { error: "Укажите корректную дату расхода" },
      400
    );
  }

  const eventKey = `expense:${crypto.randomUUID()}`;

  const result = await db.prepare(
    `INSERT INTO finance_transactions (
      type,
      amount,
      category,
      description,
      transaction_date,
      event_key
    )
    VALUES (
      'expense', ?, ?, ?, ?, ?
    )`
  ).bind(
    amount,
    category,
    description,
    date,
    eventKey
  ).run();

  await logAdminAction(db, "Добавил расход", "finance_expense", result.meta.last_row_id, {
    amount, category, description, transaction_date: date
  });
  return json({ success: true, id: result.meta.last_row_id }, 201);
}


async function updateFinanceExpense(request, db, id) {
  let body;

  try {
    body = await readBody(request);
  } catch {
    return json({ error: "Некорректные данные" }, 400);
  }

  if (!validId(id)) {
    return json({ error: "Некорректный номер расхода" }, 400);
  }

  const amount = parseRubles(body.amount);
  const category = safeText(body.category, 100);
  const description = safeText(body.description ?? "", 1000);
  const date = body.transaction_date;

  if (!amount) {
    return json({ error: "Укажите корректную сумму расхода в рублях" }, 400);
  }

  if (!category || category.length < 2) {
    return json({ error: "Укажите категорию расхода" }, 400);
  }

  if (description === null) {
    return json({ error: "Комментарий слишком длинный" }, 400);
  }

  if (!validBookingDate(date)) {
    return json({ error: "Укажите корректную дату расхода" }, 400);
  }

  const existing = await db.prepare(
    "SELECT id, type FROM finance_transactions WHERE id = ?"
  ).bind(id).first();

  if (!existing || existing.type !== "expense") {
    return json({ error: "Расход не найден" }, 404);
  }

  const result = await db.prepare(
    `UPDATE finance_transactions
     SET amount = ?, category = ?, description = ?, transaction_date = ?
     WHERE id = ? AND type = 'expense'`
  ).bind(amount, category, description, date, id).run();

  if (!result.meta.changes) {
    return json({ error: "Не удалось обновить расход" }, 404);
  }
  await logAdminAction(db, "Изменил расход", "finance_expense", id, {
    amount, category, description, transaction_date: date
  });
  return json({ success: true, id, changes: result.meta.changes });
}


// ================================================
// ФИНАНСЫ: УДАЛЕНИЕ РАСХОДА С АУДИТОМ
// ================================================

async function ensureAuditTable(db) {
  await db.prepare(
    `CREATE TABLE IF NOT EXISTS admin_audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      actor TEXT NOT NULL,
      action TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id INTEGER,
      details TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      restored_at TEXT,
      restored_transaction_id INTEGER
    )`
  ).run();

  const info = await db.prepare("PRAGMA table_info(admin_audit_log)").all();
  const columns = new Set((info.results || []).map(column => column.name));
  if (!columns.has("restored_at")) {
    await db.prepare("ALTER TABLE admin_audit_log ADD COLUMN restored_at TEXT").run();
  }
  if (!columns.has("restored_transaction_id")) {
    await db.prepare("ALTER TABLE admin_audit_log ADD COLUMN restored_transaction_id INTEGER").run();
  }
}

async function logAdminAction(db, action, entityType, entityId, details = {}) {
  await ensureAuditTable(db);
  await db.prepare(
    `INSERT INTO admin_audit_log (actor, action, entity_type, entity_id, details)
     VALUES ('owner', ?, ?, ?, ?)`
  ).bind(
    action,
    entityType,
    validId(entityId) ? Number(entityId) : null,
    JSON.stringify(details ?? {})
  ).run();
}

async function deleteFinanceExpense(request, db, id) {
  if (!validId(id)) return json({ error: "Некорректный номер расхода" }, 400);
  await ensureAuditTable(db);

  const existing = await db.prepare(
    `SELECT id, type, amount, category, description, transaction_date
     FROM finance_transactions WHERE id = ?`
  ).bind(id).first();

  if (!existing || existing.type !== "expense") {
    return json({ error: "Расход не найден. Доходы и сторно удалять нельзя." }, 404);
  }

  const details = JSON.stringify({
    amount: Number(existing.amount || 0),
    category: existing.category || "",
    description: existing.description || "",
    transaction_date: existing.transaction_date || ""
  });

  const results = await db.batch([
    db.prepare(
      `INSERT INTO admin_audit_log
       (actor, action, entity_type, entity_id, details)
       VALUES ('owner', 'Удалил расход', 'finance_expense', ?, ?)`
    ).bind(id, details),
    db.prepare(
      "DELETE FROM finance_transactions WHERE id = ? AND type = 'expense'"
    ).bind(id)
  ]);

  if (!results?.[1]?.meta?.changes) {
    return json({ error: "Не удалось удалить расход" }, 409);
  }
  return json({ success: true, id });
}

async function restoreDeletedExpense(request, db, auditId) {
  if (!validId(auditId)) return json({ error: "Некорректный номер действия" }, 400);
  await ensureAuditTable(db);

  const entry = await db.prepare(
    `SELECT id, action, entity_type, details, restored_at
     FROM admin_audit_log WHERE id = ?`
  ).bind(auditId).first();

  if (!entry || entry.action !== "Удалил расход" || entry.entity_type !== "finance_expense") {
    return json({ error: "Удалённый расход не найден в журнале" }, 404);
  }
  if (entry.restored_at) return json({ error: "Этот расход уже восстановлен" }, 409);

  let details;
  try { details = JSON.parse(entry.details || "{}"); }
  catch { return json({ error: "Данные удалённого расхода повреждены" }, 409); }

  const amount = parseRubles(details.amount);
  const category = safeText(details.category, 100);
  const description = safeText(details.description ?? "", 1000);
  const date = details.transaction_date;
  if (!amount || !category || description === null || !validBookingDate(date)) {
    return json({ error: "Невозможно восстановить расход: данные некорректны" }, 409);
  }

  const eventKey = `audit-restore:${auditId}`;
  const restoreDetails = JSON.stringify({
    restored_from_audit_id: Number(auditId), amount, category, transaction_date: date
  });

  const results = await db.batch([
    db.prepare(
      `INSERT INTO finance_transactions (
        type, amount, category, description, transaction_date, event_key
      )
      SELECT 'expense', ?, ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1 FROM admin_audit_log
        WHERE id = ? AND action = 'Удалил расход'
          AND entity_type = 'finance_expense' AND restored_at IS NULL
      )`
    ).bind(amount, category, description, date, eventKey, auditId),
    db.prepare(
      `UPDATE admin_audit_log
       SET restored_at = CURRENT_TIMESTAMP,
           restored_transaction_id = (SELECT id FROM finance_transactions WHERE event_key = ?)
       WHERE id = ? AND restored_at IS NULL`
    ).bind(eventKey, auditId),
    db.prepare(
      `INSERT INTO admin_audit_log
       (actor, action, entity_type, entity_id, details)
       SELECT 'owner', 'Восстановил расход', 'finance_expense', restored_transaction_id, ?
       FROM admin_audit_log WHERE id = ? AND restored_at IS NOT NULL`
    ).bind(restoreDetails, auditId)
  ]);

  if (!results?.[0]?.meta?.changes || !results?.[1]?.meta?.changes) {
    return json({ error: "Расход уже восстановлен или не удалось его восстановить" }, 409);
  }
  return json({ success: true, id: results[0].meta.last_row_id, audit_id: Number(auditId) });
}

async function createDatabaseBackup(db) {
  await ensureStaffScheduleTable(db);
  await ensureAuditTable(db);
  const tableNames = [
    "site_settings", "services", "staff", "staff_schedules",
    "bookings", "finance_transactions", "admin_audit_log"
  ];
  const tables = {};
  for (const table of tableNames) {
    const result = await db.prepare(`SELECT * FROM ${table} ORDER BY rowid`).all();
    tables[table] = result.results || [];
  }
  return json({
    format: "finesssim-d1-backup",
    version: 1,
    created_at: new Date().toISOString(),
    tables
  });
}

async function restoreDatabaseBackup(request, db) {
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (contentLength > 5 * 1024 * 1024) {
    return json({ error: "Файл слишком большой. Максимальный размер — 5 МБ." }, 413);
  }

  let raw;
  try {
    raw = await request.text();
  } catch {
    return json({ error: "Не удалось прочитать файл резервной копии" }, 400);
  }
  if (!raw || raw.length > 5 * 1024 * 1024) {
    return json({ error: "Файл пустой или превышает 5 МБ" }, 400);
  }

  let backup;
  try {
    backup = JSON.parse(raw);
  } catch {
    return json({ error: "Файл содержит некорректный JSON" }, 400);
  }

  const tableNames = [
    "site_settings", "services", "staff", "staff_schedules",
    "bookings", "finance_transactions", "admin_audit_log"
  ];
  if (
    !backup ||
    backup.format !== "finesssim-d1-backup" ||
    backup.version !== 1 ||
    !backup.tables ||
    typeof backup.tables !== "object" ||
    Array.isArray(backup.tables) ||
    tableNames.some(name => !Array.isArray(backup.tables[name]))
  ) {
    return json({ error: "Формат резервной копии не поддерживается или файл повреждён" }, 400);
  }

  const totalRows = tableNames.reduce((sum, name) => sum + backup.tables[name].length, 0);
  if (totalRows > 700) {
    return json({ error: "В копии слишком много строк для безопасного восстановления за один запрос (максимум 700)" }, 413);
  }

  await ensureStaffScheduleTable(db);
  await ensureAuditTable(db);

  const schemas = {};
  for (const table of tableNames) {
    const info = await db.prepare(`PRAGMA table_info("${table}")`).all();
    const columns = info.results || [];
    if (!columns.length) {
      return json({ error: "В базе отсутствует таблица " + table }, 500);
    }
    schemas[table] = columns;
    const allowed = new Set(columns.map(column => column.name));

    for (const row of backup.tables[table]) {
      if (!row || typeof row !== "object" || Array.isArray(row)) {
        return json({ error: "В копии обнаружена некорректная строка таблицы " + table }, 400);
      }
      const keys = Object.keys(row);
      if (!keys.length || keys.some(key => !allowed.has(key))) {
        return json({ error: "Структура данных таблицы " + table + " не совпадает с базой" }, 400);
      }
      for (const value of Object.values(row)) {
        if (
          value !== null &&
          typeof value !== "string" &&
          !(typeof value === "number" && Number.isFinite(value))
        ) {
          return json({ error: "В копии обнаружен недопустимый тип данных" }, 400);
        }
      }
      for (const column of columns) {
        if (
          column.notnull &&
          column.dflt_value === null &&
          !column.pk &&
          !Object.prototype.hasOwnProperty.call(row, column.name)
        ) {
          return json({ error: "В копии отсутствует обязательное поле " + column.name + " таблицы " + table }, 400);
        }
      }
    }
  }

  const deleteOrder = [
    "finance_transactions", "bookings", "staff_schedules",
    "staff", "services", "site_settings", "admin_audit_log"
  ];
  const insertOrder = [
    "site_settings", "services", "staff", "staff_schedules",
    "bookings", "finance_transactions", "admin_audit_log"
  ];

  const statements = deleteOrder.map(table =>
    db.prepare(`DELETE FROM "${table}"`)
  );

  for (const table of insertOrder) {
    const columns = schemas[table].map(column => column.name);
    for (const row of backup.tables[table]) {
      const rowColumns = columns.filter(column => Object.prototype.hasOwnProperty.call(row, column));
      const quotedColumns = rowColumns.map(column => '"' + column.replace(/"/g, '""') + '"').join(", ");
      const placeholders = rowColumns.map(() => "?").join(", ");
      const values = rowColumns.map(column => row[column]);
      statements.push(
        db.prepare(`INSERT INTO "${table}" (${quotedColumns}) VALUES (${placeholders})`).bind(...values)
      );
    }
  }

  statements.push(
    db.prepare(
      `INSERT INTO admin_audit_log (actor, action, entity_type, details)
       VALUES ('owner', 'Восстановил базу из резервной копии', 'database_backup', ?)`
    ).bind(JSON.stringify({
      backup_created_at: backup.created_at || null,
      restored_rows: totalRows
    }))
  );

  try {
    await db.batch(statements);
  } catch (error) {
    console.error("FINESSSIM backup restore failed:", error);
    return json({ error: "База не была восстановлена. Проверьте совместимость файла и текущей версии базы." }, 409);
  }

  return json({
    success: true,
    restored_rows: totalRows,
    restored_tables: tableNames.length
  });
}

async function getAdminAuditLog(db) {
  await ensureAuditTable(db);
  const result = await db.prepare(
    `SELECT id, actor, action, entity_type, entity_id, details,
            created_at, restored_at, restored_transaction_id
     FROM admin_audit_log ORDER BY id DESC LIMIT 200`
  ).all();
  return json({ entries: result.results || [] });
}

// ================================================
// ГЛАВНЫЙ ОБРАБОТЧИК API
// ================================================

async function handleRequest(request, env) {
  if (!env.DB) {
    return json({ error: "База данных DB не подключена" }, 500);
  }

  const url = new URL(request.url);
  const route = url.pathname.replace(/\/+$/, "") || "/";
  const method = request.method;
  const db = env.DB;

  // Вход владельца
  if (route === "/api/login" && method === "POST") {
    if (!validOrigin(request)) {
      return json({ error: "Запрос отклонён" }, 403);
    }

    if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET) {
      return json(
        { error: "Не настроены секреты администратора" },
        500
      );
    }

    let body;

    try {
      body = await readBody(request);
    } catch {
      return json({ error: "Некорректный запрос" }, 400);
    }

    if (
      typeof body.password !== "string" ||
      body.password.length > 200
    ) {
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
    if (!validOrigin(request)) {
      return json({ error: "Запрос отклонён" }, 403);
    }

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

  // Публичные данные
  if (route === "/api/site" && method === "GET") {
    return json(await getPublicData(db));
  }

  // Свободное время
  if (route === "/api/availability" && method === "GET") {
    return getPublicAvailability(request, db);
  }

  // Публичная запись
  if (route === "/api/bookings" && method === "POST") {
    return createPublicBooking(request, db, env);
  }

  // Остальные маршруты требуют авторизации
  if (!route.startsWith("/api/admin/")) {
    return json({ error: "Маршрут не найден" }, 404);
  }

  const authenticated = await requireOwner(request, env);

  if (!authenticated) {
    return json({ error: "Необходим вход" }, 401);
  }

  if (method !== "GET" && !validOrigin(request)) {
    return json({ error: "Запрос отклонён" }, 403);
  }

  // Настройки
  if (route === "/api/admin/settings") {
    return handleSettings(request, db, method);
  }

  // Услуги
  if (
    route === "/api/admin/services" ||
    /^\/api\/admin\/services\/\d+$/.test(route)
  ) {
    return handleServices(request, db, route, method);
  }

  // Команда
  if (
    route === "/api/admin/staff" ||
    /^\/api\/admin\/staff\/\d+$/.test(route)
  ) {
    return handleStaff(request, db, route, method);
  }

  // ==============================================
  // ФИНАНСЫ
  // ==============================================

  if (route === "/api/admin/finance" && method === "GET") {
    return getFinance(request, db);
  }

  if (
    route === "/api/admin/finance/expenses" &&
    method === "POST"
  ) {
    return createFinanceExpense(request, db);
  }

  const financeExpenseMatch = route.match(
    /^\/api\/admin\/finance\/expenses\/(\d+)$/
  );

  if (financeExpenseMatch && method === "PUT") {
    return updateFinanceExpense(request, db, Number(financeExpenseMatch[1]));
  }

  if (financeExpenseMatch && method === "DELETE") {
    return deleteFinanceExpense(request, db, Number(financeExpenseMatch[1]));
  }

  if (route === "/api/admin/backup" && method === "GET") {
    return createDatabaseBackup(db);
  }

  if (route === "/api/admin/backup/restore" && method === "POST") {
    return restoreDatabaseBackup(request, db);
  }

  if (route === "/api/admin/audit" && method === "GET") {
    return getAdminAuditLog(db);
  }

  const auditRestoreMatch = route.match(/^\/api\/admin\/audit\/(\d+)\/restore$/);
  if (auditRestoreMatch && method === "POST") {
    return restoreDeletedExpense(request, db, Number(auditRestoreMatch[1]));
  }

  // Все записи
  if (route === "/api/admin/bookings") {
    if (method === "GET") {
      return json(await getBookings(db));
    }

    if (method === "POST") {
      return createAdminBooking(request, db, env);
    }

    return json({ error: "Метод не поддерживается" }, 405);
  }

  // Отдельная запись
  const bookingMatch = route.match(
    /^\/api\/admin\/bookings\/(\d+)$/
  );

  if (bookingMatch) {
    const id = Number(bookingMatch[1]);

    if (method === "DELETE") {
      // Удаление из интерфейса фактически отменяет запись.
      // Если она была завершена, updateBooking создаст сторно дохода.
      const syntheticRequest = new Request(request.url, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          "Origin": new URL(request.url).origin
        },
        body: JSON.stringify({ status: "cancelled" })
      });

      return updateBooking(syntheticRequest, db, id);
    }

    if (method === "PUT") {
      return updateBooking(request, db, id);
    }

    return json({ error: "Метод не поддерживается" }, 405);
  }

  return json({ error: "Маршрут не найден" }, 404);
}

// ================================================
// CLOUDFLARE PAGES FUNCTION
// ================================================

export async function onRequest(context) {
  try {
    return await handleRequest(
      context.request,
      context.env
    );
  } catch (error) {
    console.error("FINESSSIM API error:", error);

    return json(
      { error: "Внутренняя ошибка сервера" },
      500
    );
  }
}
