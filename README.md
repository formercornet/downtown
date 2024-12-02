# El Downtown

### Project Overview
El Downtown is a social networking platform designed to foster meaningful interactions with a clean, minimalist design. The platform allows users to share updates, connect, and receive real-time notifications.

### Project Structure
- **Frontend**: React Native for a responsive and user-friendly UI.
- **Backend**: Flask to manage API requests and handle authentication.
- **Database**: SQLAlchemy for efficient data storage.
- **Notifications**: Real-time notifications powered by One Signal.
- **Containerization**: Docker for environment consistency.

### Scrum Workflow
- We are using Scrum to manage our development with two-week sprints.
- **Project Board**: [GitHub Project Board](https://github.com/users/formercornet/projects/1)
- **Roles**:
  - **Scrum Master**: Ali Nazeer
  - **Product Owner**: Abdelaleem
  - **Development Team**: Ali Nazeer, Abdelaleem, Ahmed Abdelsalam, Reham

### Getting Started

**1. Clone the repository**
```bash
git clone https://github.com/formercornet/El-Downtown.git
```
**2. .env Setup**
Make sure to create a .env file in the project root with the following content:
```bash
JWT_SECRET_KEY=your_secret_key
DATABASE_URL=sqlite:///yourpath/database.db
FLASK_ENV=development
ONESIGNAL_APP_ID=your_onesignal_app_id
ONESIGNAL_API_KEY=your_onesignal_api_key
```

**3. Build and run the app with Docker**
-Make sure you have Docker installed on your machine.
-From the root of the project, build and start the containers:
```bash
docker-compose up --build
```

If you pull new changes from Git that don’t affect the Dockerfile or docker-compose.yml, you can simply run:
```bash
docker-compose up
```
