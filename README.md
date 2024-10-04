# SecureChat

## Overview

SecureChat is a real-time, end-to-end encrypted chat application designed for secure, private communication. It allows users to exchange messages, images, and emojis with friends, offering features like Two-Factor Authentication (2FA) and a unique, editable message ID (ms_id) for friend requests.

## Key Features

- **End-to-End Encryption (E2EE)**: Messages and media are encrypted on the client-side using public/private key cryptography, ensuring only the sender and recipient can read them.
- **Friend System**: Users can only chat with accepted friends, using an editable **ms_id** for requests.
- **Private Message ID (ms_id)**: A unique identifier for each user, allowing for secure friend requests.
- **2FA**: Two-factor authentication using TOTP (via authenticator apps) or email-based verification.
- **Encrypted Image Sharing**: Users can securely share images, which are encrypted and only accessible to friends.
- **Emoji Support**: Users can send emojis during chats.

## Tech Stack

### Backend
- **FastAPI**: Python framework for handling APIs and real-time messaging.
- **PostgreSQL/MySQL**: Database for user data, encrypted messages, and TOTP secrets.
- **PyOTP**: Library for generating and verifying 2FA codes.
- **Cryptography Libraries**: For encryption of messages and files.

### Frontend
- **React/Vue.js**: Dynamic frontend for chat functionality.
- **Web Crypto API**: Client-side encryption and decryption of messages.
  
### Hosting & CDN
- **Cloudflare**: CDN for performance and security.
- **Free Hosting Platforms**: Backend deployed on a free hosting platform (e.g., Heroku or Vercel).

## Installation

### Prerequisites

- **Python 3.x**
- **Node.js and npm** (for frontend)
- **PostgreSQL or MySQL**

### Backend Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/your-repo/securechat.git
   cd securechat
   ```

2. Install the dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Set up the database:

   - Create a PostgreSQL or MySQL database.
   - Update the `.env` file with your database URL.

4. Run the server:

   ```bash
   uvicorn main:app --reload
   ```

### Frontend Setup

1. Navigate to the frontend directory:

   ```bash
   cd frontend
   ```

2. Install frontend dependencies:

   ```bash
   npm install
   ```

3. Run the frontend:

   ```bash
   npm run serve
   ```

### Running Tests

To run backend tests:

```bash
pytest
```

### Environment Variables

Create a `.env` file with the following environment variables:

```bash
DATABASE_URL=postgresql://user:password@localhost/dbname
SECRET_KEY=your_secret_key
```

## Project Structure

```plaintext
securechat/
├── backend/
│   ├── app/
│   ├── tests/
│   └── main.py
├── frontend/
│   ├── public/
│   ├── src/
│   └── main.js
└── README.md
```

## Security Features

- **End-to-End Encryption (E2EE)** for all messages and files.
- **TOTP-based 2FA** for added account security.
- **Editable ms_id** for secure

 friend management.
  
## License

Licensed under the MIT License.
```
