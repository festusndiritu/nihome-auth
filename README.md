# FastAPI Authentication API for niHome

This project demonstrates how to use **FastAPI** to build a full authentication API. It includes features such as:

- User **Login**
- User **Registration**
- **Password Reset**
- **OTP Verification**

It also integrates with **Gmail API** to send OTP emails.

## Technologies Used

- **FastAPI** (Backend framework)
- **MongoDB** (Database)
- **Gmail API** (For sending OTP emails)
- **HTML5 & CSS3** (Frontend)
- **JavaScript** (For API calls and toast notifications)

## Installation & Setup

### Prerequisites
- Python 3.9+
- MongoDB (local or cloud-based)
- Gmail API credentials

### Steps to Run Locally

1. **Clone the repository:**
   ```bash
   git clone https://github.com/festusndiritu/nihome-auth.git
   cd nihome-auth
   ```

2. **Create a virtual environment & activate it:**
   ```bash
   python -m venv env
   source env/bin/activate  # On Windows use `env\Scripts\activate`
   ```

3. **Install dependencies:**
   ```bash
   cd api/app
   pip install -r requirements.txt
   ```

4. **Set up environment variables:**
   Create a `.env` file in api/app folder and add the following:
   ```env
   SECRET_KEY="your_secret_key"
   MONGO_URI="your_mongo_connection_string"
   GMAIL_CLIENT_ID="your_gmail_client_id"
   GMAIL_PROJECT_ID="your_gmail_project_id"
   GMAIL_CLIENT_SECRET="your_gmail_client_secret"
   ```

5. **Run the application:**
   ```bash
   uvicorn main:app --reload
   ```

6. **Access API documentation:**
   - Swagger UI: [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs)
   - Redoc UI: [http://127.0.0.1:8000/redoc](http://127.0.0.1:8000/redoc)

## Important Notes
- This project **cannot run on a serverless platform** like Vercel, as it generates a `token.json` file needed for the Gmail API. This file must be stored persistently on the server.
- Ensure your Gmail API credentials are properly configured to allow sending emails.

## Features & Endpoints

| Feature | Endpoint |
|---------|----------|
| Register | `POST /auth/register` |
| Login | `POST /auth/login` |
| Send OTP | `POST /auth/forgot_password` |
| Verify OTP | `POST /auth/verify_otp` |
| Reset Password | `POST /auth/reset_password` |

## Frontend
The frontend is built using **HTML5, CSS3, and JavaScript**. It includes simple UI elements to:
- Display the auth flow UI
- Display toast notifications
- Make API calls to authentication endpoints

## Contributing
Feel free to fork this repository and submit a pull request with improvements or additional features.

## License
This project is licensed under the MIT License.
