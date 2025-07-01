# ☁️ Secure Containerized Web App – Hardening & Evaluation

This project demonstrates the process of identifying vulnerabilities and implementing container hardening for a web and database application deployed via Docker.


## 🔧 Key Features

- Docker-based deployment of PHP/NGINX and MariaDB
- Switched base images to hardened Debian/MariaDB
- Enforced runtime security: `--read-only`, `--cap-drop=ALL`, `--no-new-privileges`
- Used `tmpfs` and limited access volumes
- Configured static IPs on a custom Docker network
- Implemented persistent storage with named volumes
- Hardened system with custom `mysqld.cnf`, `php.ini`, `nginx.conf`

## 🔍 Tools Used

- **Trivy**: Container vulnerability scanning
- **Docker**: Container deployment and runtime restriction
- **Makefiles**: Build automation
- **Seccomp & strace**: Syscall restriction analysis

## 🧪 Security Test Results

| Test                     | Outcome        |
|--------------------------|----------------|
| SQL Injection            | Prevented ✅     |
| Cross-Site Scripting     | Blocked ✅       |
| Data Persistence         | Retained ✅      |
| Privilege Escalation     | Denied ✅        |
| File Write Protection    | Enforced ✅      |
| Seccomp Restrictions     | Applied ✅       |

---

## 🔐 Hardening Goals Achieved

- Least privilege for users and processes
- Immutable containers with enforced constraints
- Secure inter-container communication
- Docker best practices followed (CIS benchmark aligned)

---

## 🧠 Author

**Yash Bhootra**  
MSc Cyber Security Engineering  
University of Warwick  
GitHub: [@2smooth4u](https://github.com/2smooth4u)

