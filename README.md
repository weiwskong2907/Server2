# php-forum
This project is a family and friends forum website that includes user authentication, registration, and an admin panel for managing content and users.

## Features
- **User Authentication**: Users can register and log in to access the forum.
- **Admin Panel**: Admins can manage users, forums, and invitations.
- **Forum Management**: Create, edit, and delete forum categories and topics.
- **User Management**: View, edit, and delete user accounts, as well as manage roles.
- **Invitation System**: Admins can send invitations for registration.

## Directory Structure
```
Server2
├── admin
│   ├── dashboard.php
│   ├── manage-forums.php
│   ├── manage-users.php
│   └── manage-invites.php
├── config
│   ├── config.php
│   └── database.php
├── includes
│   ├── auth.php
│   ├── functions.php
│   ├── header.php
│   ├── footer.php
│   └── session.php
├── assets
│   ├── css
│   │   └── style.css
│   └── js
│       └── main.js
├── classes
│   ├── Database.php
│   ├── User.php
│   ├── Forum.php
│   ├── Post.php
│   └── Invite.php
├── pages
│   ├── login.php
│   ├── register.php
│   ├── forum.php
│   ├── thread.php
│   └── profile.php
├── .htaccess
├── index.php
└── README.md
```

## Setup Instructions
1. Clone the repository to your local server.
2. Configure the database settings in `config/database.php`.
3. Set up the database schema as per the provided SQL scripts (if any).
4. Access the application via your web browser at `http://your-server/php-forum`.

## Technologies Used
- PHP
- MySQL
- HTML/CSS
- JavaScript

## License
This project is licensed under the MIT License.