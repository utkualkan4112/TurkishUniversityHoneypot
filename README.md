# TurkishUniversityHoneypot

This repository contains the code for a Flask-based web application that provides a platform for university news. The application uses MySQL as the database backend.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

Before you begin, ensure you have the following installed:
- Python 3
- PostgreSQL
- Flask and other Python dependencies

### Installing

A step-by-step series of examples that tell you how to get a development environment running.

#### 1. Clone the Repository

Clone this repository to your local machine:

```bash
git clone https://github.com/utkualkan4112/TurkishUniversityHoneypot
cd university-news-portal
```

#### 2. Install Python Dependencies

Install the required Python packages:

```bash
pip install -r requirements.txt
```
#### 3. PostgreSQL Setup
1. Open PostgreSQL shell

2. Create Database:
```sql
CREATE DATABASE Newss;
```
3. Switch to the database:
```sql
\c Newss;
```
4. Create tables:
```sql
CREATE TABLE "user" (
  id SERIAL PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  password_hash VARCHAR(512) NOT NULL,
  is_admin BOOLEAN DEFAULT FALSE,
  profile_image VARCHAR(255),
  about TEXT
);
```
```sql
CREATE TABLE comment (
  id SERIAL PRIMARY KEY,
  content TEXT NOT NULL,
  user_id INTEGER REFERENCES "user" (id) ON DELETE SET NULL,
  article_title VARCHAR(200)
);
```
5. Add initial data (optional):
```sql
INSERT INTO "user" (id, username, password_hash, is_admin, profile_image, about)
VALUES
  (3, 'zort', 'zort', false, 'e2b55a9b-7fcd-4369-9876-8918e5182cb6.jpeg', 'Zort bir yaşam tarzıdır'),
  (5, 'Naber', 'Xogta7-qomwux-cenxog', false, NULL, NULL),
  (6, 'admin', 'admin', true, '2a21385f-d511-468a-bcf8-0985d94000bc.jpeg', 'Welcome to Game'),
  (8, 'Utkualkan', 'Alkanutku', false, 'da6da958-f15e-4424-8b30-52cf0e3f2c3b.jpeg', 'Ponçik bir ayı'),
  (9, 'Süleyman5252', 'SızıntıYapma', false, 'e6589e17-25e0-45a8-8fd1-9b3959666619.jpg', 'Hayat kısa ama sen uzunsun'),
  (10, 'dila', 'dila', false, NULL, NULL),
  (11, 'yeni', 'yeni', false, NULL, 'XXE Test');
```
```sql
INSERT INTO "comment" (id, content, user_id, article_title)
VALUES
  (23, 'Bu inanılmaz bir olay gerçekten', 8, 'Harran Üniversitesi Öğrenci Yurdunda Asansör Protestosu'),
  (24, 'gaydırı gukbak cemile', 8, 'Kazak hekimler ZBEÜ Rektörünü ziyaret etti'),
  (25, 'Helal olsun vallaha', 9, 'Harran Üniversitesi Öğrenci Yurdunda Asansör Protestosu'),
  (26, 'Zorttiriti zortt', 9, ''),
  (27, 'zortititirit', 9, 'Burdur''da Üniversite Öğrencileri İsrail''in Saldırılarını Kınadı'),
  (28, 'evli mi', 9, ''),
  (29, 'Aman aman neler olucak acaba', 9, 'SAÜ, Araştırma Üniversitesi Aday İzleme Programı''na alındı'),
  (30, 'çok kalabalık', 10, 'Harran Üniversitesi Öğrenci Yurdunda Asansör Protestosu'),
  (31, 'Heyoo', 11, 'NEVÜ''ye 42 öğretim elemanı alınacak');
```

#### 4. Configure Flask App

Update SQLALCHEMY_DATABASE_URI in your Flask application (line 307):

```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://your_username:your_password@localhost/Newss'
```

#### Running the Application
Run the python application:

```bash
python App.py
```

The application should now be running on http://localhost:5000.


### Notes:

- Replace placeholders (like `your_username`, `your_password`) with your PostgreSQL credentials.
- Make sure your PostgreSQL service uses port 5432
