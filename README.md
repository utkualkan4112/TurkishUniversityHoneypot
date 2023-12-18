# TurkishUniversityHoneypot

# University News Portal

This repository contains the code for a Flask-based web application that provides a platform for university news. The application uses MySQL as the database backend.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before you begin, ensure you have the following installed:
- Python 3
- MySQL
- Flask and other Python dependencies

### Installing

A step-by-step series of examples that tell you how to get a development environment running.

#### 1. Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/yourusername/university-news-portal.git
cd university-news-portal
```

####2. Install Python Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```
####3. MySQL Setup

Start MySQL Service for MacOs

```bash
brew services start mysql
```

Secure MySQL Installation

```bash
mysql_secure_installation
```

Create Database and User

```sql
CREATE DATABASE News;
CREATE USER 'your_username'@'localhost' IDENTIFIED BY 'your_password';
GRANT ALL PRIVILEGES ON News.* TO 'your_username'@'localhost';
FLUSH PRIVILEGES;
```

####4. Configure Flask App

Update SQLALCHEMY_DATABASE_URI in your Flask application:

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://your_username:your_password@localhost/News'
```

####5. Initialize Database

```bash
flask db init
flask db migrate
flask db upgrade
```

####Running the Application
Run the Flask application:

```bash
flask run
```

The application should now be running on http://localhost:5000.


### Notes:

- Replace placeholders (like `your_username`, `your_password`, `https://github.com/yourusername/university-news-portal.git`) with actual values.
- Ensure you have a `requirements.txt` file in your repository that lists all the Python packages required for your project.
- You may want to add a `CONTRIBUTING.md` and a `LICENSE.md` file to your repository if mentioned in the README.

