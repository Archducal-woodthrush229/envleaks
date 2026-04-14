# 🔎 envleaks - Find exposed secrets before they spread

[![Download envleaks](https://img.shields.io/badge/Download-Envleaks-blue?style=for-the-badge&logo=github)](https://github.com/Archducal-woodthrush229/envleaks)

## 📥 Download

Use this link to visit the page and download envleaks for Windows:

https://github.com/Archducal-woodthrush229/envleaks

## 🖥️ What envleaks does

envleaks scans codebases, git history, and Docker images for secrets that should not be public. It looks for things like API keys, access tokens, passwords, private keys, and other sensitive values that may have slipped into files by mistake.

Use it to check:

- Local code folders
- Git repositories with old commits
- Docker images stored on your machine
- Project files before you share them with others

## ✅ What you need

Before you start, make sure you have:

- A Windows PC
- Internet access
- Permission to scan the files or images you want to check
- Enough free space for the project you plan to scan

If the download page offers a Windows file, use that file first. If it offers a ZIP file, extract it before running it.

## 🚀 Get envleaks on Windows

1. Open this page in your browser:
   https://github.com/Archducal-woodthrush229/envleaks

2. Look for a Windows download in the release files or project files.

3. Download the file to your computer.

4. If the file is in a ZIP folder, right-click it and choose Extract All.

5. Open the extracted folder.

6. Find the program file and double-click it to run.

7. If Windows asks for permission, choose Yes.

## 🔍 How to scan a folder

After envleaks opens, you can scan a folder that holds source code.

1. Choose the folder you want to check.
2. Start a scan.
3. Wait for the results.
4. Review any items marked as possible secrets.

Common matches include:

- `.env` files
- Config files
- Sample files with real values
- Hardcoded tokens in code
- Keys in old commits

## 🕘 How to scan git history

envleaks can inspect past commits too. This helps you find secrets that were removed from current files but still live in history.

Use it when:

- A secret was committed by mistake
- A token was later deleted from the main branch
- You want to review an old project before sharing it

To scan git history:

1. Open the repository folder.
2. Select the history scan option.
3. Start the scan.
4. Review the commit list and any secret matches.

## 🐳 How to scan Docker images

You can also check Docker images for exposed values.

1. Choose the Docker image you want to inspect.
2. Start the image scan.
3. Review file layers and found secrets.
4. Remove or replace any sensitive data before you publish the image.

This is useful for:

- Images built during local testing
- Images shared with a team
- Images that may contain build-time secrets

## ⚙️ Simple setup tips

If envleaks asks for a path, use the full folder path. On Windows, that often looks like this:

- `C:\Users\YourName\Documents\Project`

If you want to scan a git repo, pick the folder that contains the `.git` directory.

If you want to scan a Docker image, make sure the image already exists on your system.

## 📁 Common scan targets

envleaks works best on places where secrets often end up by mistake.

Good targets include:

- Project source folders
- Backup folders
- Exported code archives
- `.env` files
- YAML and JSON config files
- Docker build files
- Old git branches
- Clone folders from shared drives

## 🧰 What you may find

envleaks may flag items such as:

- Cloud access keys
- Database passwords
- SSH private keys
- JWT tokens
- Service account files
- Session tokens
- Webhook secrets
- API credentials

Not every match is a real secret. Some are test values, examples, or dummy strings. Review each item before you act on it.

## 🧪 Best way to use it

Use envleaks at these times:

- Before you push code to a public repo
- Before you send code to another person
- After a secret leak cleanup
- Before you build and ship a Docker image
- When you audit an old codebase

A regular scan can help you catch problems early.

## 🛠️ If the app does not open

If Windows does not start the app:

1. Check that the download finished.
2. Make sure the file was not left inside a ZIP folder.
3. Try right-clicking the file and opening it again.
4. Confirm that your Windows account can run downloaded apps.
5. Revisit the download page and get the file again if needed.

## 🔐 Good habits when you use envleaks

Keep your results clean by using these habits:

- Store secrets in a secure vault
- Move sensitive values out of code
- Replace hardcoded values with environment variables
- Review `.env` files before sharing them
- Check old commits before you publish a repo
- Rebuild Docker images after removing sensitive data

## 🧭 Topics covered

envleaks is built for:

- CLI use
- DevSecOps workflows
- Security scanning
- Secret detection
- Python-based tools
- Hacker-focused testing and review

## 📌 Quick start checklist

- Open the download page
- Download envleaks for Windows
- Extract the file if needed
- Run the app
- Scan a folder, git repo, or Docker image
- Review any secrets it finds
- Fix exposed values before sharing your work