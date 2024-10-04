the backend files of the app

Here's a breakdown of the backend structure and additional functionality to support the frontend directory:

Backend Directory Structure (Updated)
graphql
Copy code
backend/
├── app/
│   ├── api/
│   │   ├── auth.py               # Handles user authentication, registration, and 2FA
│   │   ├── friends.py            # Manages friend requests, accepts, declines, and listing
│   │   ├── messages.py           # Manages message creation, encryption, and retrieval
│   │   ├── settings.py           # Manages user account settings (password, ms_id, 2FA, sessions)
│   │   └── media.py              # Manages encrypted image uploads and retrieval
│   ├── core/
│   │   ├── encryption.py         # Handles client-side encryption/decryption of messages and images
│   │   ├── websockets.py         # WebSocket manager for real-time messaging
│   │   └── security.py           # Handles TOTP generation and validation for 2FA
│   ├── models/
│   │   ├── user.py               # User model with password, ms_id, public/private keys, 2FA secret
│   │   ├── friend.py             # Friend request model to handle relationships between users
│   │   ├── message.py            # Message model with sender, receiver, encrypted content
│   │   └── media.py              # Media model for handling encrypted images
│   ├── db/
│   │   ├── connection.py         # Database connection manager (PostgreSQL/MySQL)
│   │   └── migrations.py         # Database migration scripts
│   ├── services/
│   │   ├── email_service.py      # Service for sending verification and 2FA-related emails
│   │   └── session_manager.py    # Manages user session control (revoking, terminating sessions)
│   ├── main.py                   # FastAPI app entry point
│   ├── config.py                 # Application configuration (e.g., secret keys, database settings)
│   └── requirements.txt          # Python package dependencies
└── Dockerfile                    # Docker configuration for backend deployment
Backend Functionality (Updated)
1. Authentication (auth.py)
/register (POST):

Purpose: User registration with public/private key handling and ms_id generation.
Backend Change: Make sure the public key is stored securely in the database, while the private key never leaves the client. Add ms_id field to registration process.
/login (POST):

Purpose: User login and 2FA authentication.
Backend Change: Now includes TOTP or email verification as part of the login flow if 2FA is enabled.
/logout (POST):

Purpose: Terminates the user session.
Backend Change: Clear session tokens and active WebSocket connections upon logout.
2. Friend System (friends.py)
/friends/request (POST):

Purpose: Send friend request using ms_id.
Backend Change: Ensure friend requests are tied to the unique, editable ms_id of the recipient, not the username.
/friends/accept (POST):

Purpose: Accept friend requests.
Backend Change: Allow the system to update friend relationships and notify both users via WebSocket about the new connection.
/friends/list (GET):

Purpose: Retrieve a list of the user’s friends.
Backend Change: Include friend status (online/offline) and ms_id for chat initiation.
3. Messaging System (messages.py)
/messages/send (WebSocket):

Purpose: Send real-time encrypted messages to a friend.
Backend Change: Integrate end-to-end encryption for text, emojis, and images before transmission. Only the recipient can decrypt the message.
/messages/retrieve (GET):

Purpose: Retrieve chat history between friends.
Backend Change: Ensure that all messages are stored in their encrypted form in the database. When messages are retrieved, they remain encrypted unless decrypted client-side by the user’s private key.
4. Image Media (media.py)
/media/upload (POST):

Purpose: Handle image uploads from users.
Backend Change: Encrypt the image client-side before sending it to the server. The server only stores the encrypted image. The recipient will decrypt the image using their private key.
/media/retrieve/{message_id} (GET):

Purpose: Retrieve the encrypted image for a specific message.
Backend Change: Ensure the image is only accessible to the recipient who holds the decryption key.
5. User Account Settings (settings.py)
/profile/update-ms_id (POST):

Purpose: Allow users to change their unique ms_id.
Backend Change: Make the ms_id a unique field and ensure it can be updated. All friend requests are tied to the ms_id, and updating it should reflect across the friend system.
/profile/enable-2fa (POST):

Purpose: Enable 2FA using TOTP.
Backend Change: Store the user-specific TOTP secret securely in the database.
/profile/revoke-sessions (POST):

Purpose: Allow users to revoke all active sessions.
Backend Change: Implement session management logic to terminate all user sessions, including active WebSocket connections.
6. Security and Encryption (core/encryption.py)
encrypt_message (Function):

Purpose: Encrypt a message before sending it.
Backend Change: Uses the recipient’s public key for encryption, ensuring only they can decrypt the message with their private key.
decrypt_message (Function):

Purpose: Decrypt a message received.
Backend Change: Decrypts the message using the user’s private key. The server only holds and transmits encrypted data.
encrypt_image (Function):

Purpose: Encrypt an image file before uploading it.
Backend Change: Encrypts the image using a symmetric key shared between the sender and recipient. The server stores the encrypted image.
7. 2FA (TOTP) System (security.py)
generate_totp (Function):

Purpose: Generate a TOTP secret for 2FA.
Backend Change: Assign each user their own TOTP secret, which will be used for generating time-based one-time passwords (TOTP).
verify_totp (Function):

Purpose: Verify the TOTP code during login or 2FA setup.
Backend Change: Validate the TOTP against the user-specific secret stored in the database. If the code is valid, the user gains access to their account.
