# Nectar Admin Customer Details & Brute-Force Protection System Documentation

This document describes the newly implemented production-grade backend features for customer analytics, internal admin notes, and security hardening (brute-force protection) in the Nectar e-commerce backend.

---

## 1. Security & Brute-Force Lockout Rules

To protect the platform against dictionary and brute-force credential attacks, we have implemented an active lockout policy for **Email Login** (`/api/v1/auth/email/login`) and **Admin Login** (`/api/v1/auth/admin/signup` [which is the admin login route]).

### Lockout Rules:
1. **Trigger threshold**: **3 consecutive failed login attempts** with incorrect passwords.
2. **Lock duration**: **20 minutes** (from the timestamp of the 3rd failed attempt).
3. **Lock mechanism**:
   - The lock is written directly to the database user document under the field `loginLockedUntil` and cached in Redis with a 20-minute TTL for low-latency request rejection without querying the database.
   - Any attempt to login while locked returns `429 Too Many Requests` immediately, along with the remaining lock time in milliseconds and the exact locked-until timestamp.
4. **How to unlock**:
   - **Automatic expiry**: The lock naturally expires after 20 minutes.
   - **Password reset**: If a user performs a successful password reset (`/api/v1/auth/reset-password`), the active lock is cleared, and their failed login counter resets to 0.
   - **Admin action**: An admin can manually unblock any locked customer using the unblock endpoint (`POST /api/v1/admin/customers/:id/unblock`).

---

## 2. Schema Changes & New Fields

### A. Existing `users` Collection Additions

We added 5 new optional security/device metadata fields to the `users` schema:

| Field Name | Type | Default | Index | Description |
| :--- | :--- | :--- | :--- | :--- |
| `failedLoginCount` | `Number` | `0` | No | Consecutive failed login count. Resets on login success. |
| `loginLockedUntil` | `Date` | `null` | Yes | Timestamp until which the account is blocked from logging in. |
| `passwordChangedAt`| `Date` | `null` | No | Timestamp of the last password change. Useful for auditing. |
| `lastKnownIp` | `String` | `null` | No | Last recorded public IP address of the user (hidden by default). |
| `appVersion` | `String` | `null` | No | Last reported version of the mobile app. |

### B. Device Schema Enhancements (inside `User.device` array)

The `deviceSchema` subdocument was enhanced to capture more detailed device fingerprints:

| Field Name | Type | Default | Description |
| :--- | :--- | :--- | :--- |
| `deviceModel` | `String` | `null` | The device model (e.g. `"iPhone 14 Pro"`, `"Pixel 7"`). |
| `osVersion` | `String` | `null` | Operating System version (e.g. `"iOS 16.5"`, `"Android 13"`). |
| `appVersion` | `String` | `null` | App version reported when registering the device. |

### C. `LoginHistory` Collection (New)
Records a complete audit trail of login/security events. Automatically pruned after **90 days** using a MongoDB TTL index.

- **Collection Name**: `loginhistories`
- **Fields**:
  - `userId`: `ObjectId` (references `users`, indexed)
  - `event`: `String` (enum: `"login_success"`, `"login_failed"`, `"account_locked"`, `"account_unlocked"`, `"password_changed"`, `"otp_verified"`, `"logout"`)
  - `provider`: `String` (enum: `"email"`, `"google"`, `"facebook"`, `"unknown"`)
  - `ip`: `String` (client public IP)
  - `userAgent`: `String` (user agent string)
  - `platform`: `String` (enum: `"android"`, `"ios"`, `"web"`, `"unknown"`)
  - `deviceId`: `String` (unique device identifier)
  - `appVersion`: `String` (client app version)
  - `meta`: `Mixed` (optional event metadata)
  - `createdAt`: `Date` (auto-created timestamp)

### D. `AdminNote` Collection (New)
Stores internal administrative notes for customers.

- **Collection Name**: `adminnotes`
- **Fields**:
  - `userId`: `ObjectId` (references `users` customer, indexed)
  - `adminId`: `ObjectId` (references `users` admin)
  - `note`: `String` (max 2000 characters, trimmed)
  - `createdAt`: `Date`
  - `updatedAt`: `Date`

---

## 3. New API Endpoints (Admin Role Only)

All endpoints below require a valid Admin JSON Web Token in the `Authorization` header (`Bearer <token>`).

### Endpoint List:

| Method | Endpoint Path | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/admin/customers/:id` | Returns customer overview, status details, security metadata, and registered devices. |
| `GET` | `/api/v1/admin/customers/:id/orders` | Returns lifetime e-commerce statistics and a paginated list of orders. |
| `GET` | `/api/v1/admin/customers/:id/payment-summary` | Returns detailed payment summary (lifetime spending, paid vs failed orders). |
| `GET` | `/api/v1/admin/customers/:id/wishlist-cart` | Returns cart contents (items, total quantity, total price) and wishlist items. |
| `GET` | `/api/v1/admin/customers/:id/timeline` | Returns a combined chronological feed of activities (login events, orders, bookmarks). |
| `GET` | `/api/v1/admin/customers/:id/login-history` | Returns paginated security and login event history. |
| `GET` | `/api/v1/admin/customers/:id/chat-summary` | Returns support chat summary (unread message counts, active chats). |
| `POST` | `/api/v1/admin/customers/:id/unblock` | Admin action to manually unlock a brute-force locked customer. |
| `GET` | `/api/v1/admin/customers/:id/notes` | Get all admin notes for a customer (paginated). |
| `POST` | `/api/v1/admin/customers/:id/notes` | Add a new administrative internal note. |
| `PUT` | `/api/v1/admin/customers/:id/notes/:noteId` | Update an existing admin note (limited to the admin who created it). |
| `DELETE` | `/api/v1/admin/customers/:id/notes/:noteId` | Delete an admin note. |

---

## 4. Mobile App Integration Instructions

To ensure the backend collects accurate device signatures and security logs, the React Native / mobile client **must** pass specific headers with every request:

### Required Custom Headers:

| Header Name | Value / Format | Example Value | Description |
| :--- | :--- | :--- | :--- |
| `X-Platform` | `"android"` \| `"ios"` \| `"web"` | `ios` | Identifies the request platform. |
| `X-App-Version` | SemVer string | `1.0.4` | App version code. |
| `X-Device-Id` | Unique hardware ID | `F839A2-BC23-90A1` | Unique device identifier. |

*Note: The backend automatically extracts the public IP address from the request (supporting `X-Forwarded-For` and `X-Real-IP` proxy headers).*

---

## 5. Request & Response Examples

### A. Locked Out Login Response (Brute Force Triggered)
**POST** `/api/v1/auth/email/login` with incorrect credentials on the 3rd attempt:

* **Status Code**: `429 Too Many Requests`
* **Response Body**:
```json
{
  "success": false,
  "message": "Account temporarily locked due to too many failed login attempts. Please try again in 20 minute(s) or contact support.",
  "data": {
    "lockedUntil": "2026-06-29T02:45:00.000Z",
    "remainingMs": 1200000
  }
}
```

---

### B. GET Customer Overview
**GET** `/api/v1/admin/customers/645b23e19f120004a2001bb3`

* **Status Code**: `200 OK`
* **Response Body**:
```json
{
  "success": true,
  "message": "Customer details retrieved successfully",
  "data": {
    "profile": {
      "id": "645b23e19f120004a2001bb3",
      "name": "Jane Doe",
      "email": "janedoe@example.com",
      "avatar": "https://res.cloudinary.com/nectar/image/upload/v1234/user-avatar.jpg",
      "provider": "email",
      "role": "user",
      "notificationEnabled": true,
      "appVersion": "1.0.4",
      "location": {
        "latitude": 23.8103,
        "longitude": 90.4125,
        "country": "Bangladesh",
        "city": "Dhaka"
      },
      "joinedAt": "2026-05-15T12:00:00.000Z",
      "updatedAt": "2026-06-29T02:14:00.000Z"
    },
    "status": {
      "isActive": true,
      "isVerified": true,
      "lastLoginAt": "2026-06-29T02:00:00.000Z",
      "lastKnownIp": "103.112.54.9"
    },
    "security": {
      "isLocked": false,
      "loginLockedUntil": null,
      "lockRemainingMs": 0,
      "failedLoginCount": 0,
      "passwordChangedAt": "2026-06-10T10:30:00.000Z",
      "redisLockActive": false
    },
    "devices": [
      {
        "platform": "ios",
        "deviceId": "F839A2-BC23-90A1",
        "deviceModel": "iPhone 14 Pro",
        "osVersion": "16.5",
        "appVersion": "1.0.4",
        "lastActive": "2026-06-29T02:00:00.000Z"
      }
    ]
  }
}
```

---

### C. GET Order Summary
**GET** `/api/v1/admin/customers/645b23e19f120004a2001bb3/orders?page=1&limit=2`

* **Status Code**: `200 OK`
* **Response Body**:
```json
{
  "success": true,
  "message": "Customer order summary retrieved",
  "pagination": {
    "total": 12,
    "page": 1,
    "limit": 2,
    "totalPages": 6
  },
  "data": {
    "summary": {
      "totalOrders": 12,
      "totalSpent": 450.75,
      "avgOrderValue": 37.56,
      "byStatus": {
        "pending": 1,
        "confirmed": 1,
        "shipped": 2,
        "delivered": 7,
        "cancelled": 1
      },
      "byPayment": {
        "paid": 11,
        "failed": 0
      }
    },
    "orders": [
      {
        "_id": "645b3c299f120004a2002cc5",
        "orderStatus": "delivered",
        "paymentStatus": "paid",
        "totalPrice": 45.50,
        "totalQuantity": 3,
        "items": [
          {
            "product": "645b10f29f120004a2000aa1",
            "name": "Organic Bananas",
            "image": "https://example.com/bananas.jpg",
            "price": 1.50,
            "quantity": 3
          }
        ],
        "shippingAddress": {
          "address": "123 Elm St",
          "city": "Dhaka",
          "country": "Bangladesh",
          "phone": "+8801700000000"
        },
        "createdAt": "2026-06-28T18:00:00.000Z"
      }
    ]
  }
}
```

---

### D. GET Activity Timeline
**GET** `/api/v1/admin/customers/645b23e19f120004a2001bb3/timeline?page=1&limit=3`

* **Status Code**: `200 OK`
* **Response Body**:
```json
{
  "success": true,
  "message": "Customer activity timeline retrieved",
  "pagination": {
    "total": 32,
    "page": 1,
    "limit": 3,
    "totalPages": 11
  },
  "data": [
    {
      "type": "auth",
      "description": "Successful login",
      "meta": {
        "event": "login_success",
        "provider": "email",
        "platform": "ios",
        "ip": "103.112.54.9"
      },
      "timestamp": "2026-06-29T02:00:00.000Z"
    },
    {
      "type": "wishlist",
      "description": "Added \"Fresh Red Apples\" to wishlist",
      "meta": {
        "productId": "645b10f29f120004a2000aa8",
        "productName": "Fresh Red Apples",
        "productImage": "https://example.com/apples.jpg"
      },
      "timestamp": "2026-06-28T22:30:00.000Z"
    },
    {
      "type": "order",
      "description": "Order delivered — $45.50",
      "meta": {
        "orderId": "645b3c299f120004a2002cc5",
        "orderStatus": "delivered",
        "paymentStatus": "paid",
        "totalPrice": 45.50
      },
      "timestamp": "2026-06-28T18:00:00.000Z"
    }
  ]
}
```

---

### E. GET Login History
**GET** `/api/v1/admin/customers/645b23e19f120004a2001bb3/login-history?page=1&limit=2`

* **Status Code**: `200 OK`
* **Response Body**:
```json
{
  "success": true,
  "message": "Login history retrieved",
  "pagination": {
    "total": 24,
    "page": 1,
    "limit": 2,
    "totalPages": 12
  },
  "data": [
    {
      "_id": "645c32109f120004a2003dd1",
      "event": "login_success",
      "provider": "email",
      "ip": "103.112.54.9",
      "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X)",
      "platform": "ios",
      "deviceId": "F839A2-BC23-90A1",
      "appVersion": "1.0.4",
      "createdAt": "2026-06-29T02:00:00.000Z"
    },
    {
      "_id": "645c320a9f120004a2003dd0",
      "event": "login_failed",
      "provider": "email",
      "ip": "103.112.54.9",
      "userAgent": "Mozilla/5.0 (iPhone; CPU iPhone OS 16_5 like Mac OS X)",
      "platform": "ios",
      "deviceId": "F839A2-BC23-90A1",
      "appVersion": "1.0.4",
      "meta": {
        "attempt": 1,
        "maxAttempts": 3
      },
      "createdAt": "2026-06-29T01:58:30.000Z"
    }
  ]
}
```

---

### F. GET Support Chat Summary
**GET** `/api/v1/admin/customers/645b23e19f120004a2001bb3/chat-summary`

* **Status Code**: `200 OK`
* **Response Body**:
```json
{
  "success": true,
  "message": "Customer chat summary retrieved",
  "data": {
    "summary": {
      "totalChats": 1,
      "totalMessages": 45,
      "unreadMessages": 2,
      "lastMessage": {
        "content": "Hello, is my delivery on the way?",
        "sentAt": "2026-06-29T01:30:00.000Z"
      }
    },
    "recentChats": [
      {
        "chatId": "645b5e199f120004a2002ff1",
        "lastMessage": "Hello, is my delivery on the way?",
        "lastUpdated": "2026-06-29T01:30:00.000Z",
        "otherParticipant": {
          "id": "645a11bc9f120004a2000001",
          "name": "Nectar Support Agent",
          "email": "support@nectar.com",
          "role": "admin",
          "avatar": "https://example.com/support-avatar.jpg"
        }
      }
    ]
  }
}
```

---

### G. POST Add Admin Note
**POST** `/api/v1/admin/customers/645b23e19f120004a2001bb3/notes`
* **Request Body**:
```json
{
  "note": "Customer contacted support regarding late delivery. Refunded shipping fee."
}
```
* **Status Code**: `201 Created`
* **Response Body**:
```json
{
  "success": true,
  "message": "Note added successfully",
  "data": {
    "noteId": "645c40aa9f120004a2004ee2",
    "note": "Customer contacted support regarding late delivery. Refunded shipping fee.",
    "userId": "645b23e19f120004a2001bb3",
    "adminId": "645a11bc9f120004a2000001",
    "createdAt": "2026-06-29T02:20:00.000Z"
  }
}
```

---

### H. POST Unblock Manually
**POST** `/api/v1/admin/customers/645b23e19f120004a2001bb3/unblock`

* **Status Code**: `200 OK`
* **Response Body**:
```json
{
  "success": true,
  "message": "Account unlocked successfully",
  "data": {
    "userId": "645b23e19f120004a2001bb3",
    "email": "janedoe@example.com",
    "unlockedAt": "2026-06-29T02:22:00.000Z"
  }
}
```
