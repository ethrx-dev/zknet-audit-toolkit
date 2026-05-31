from pathlib import Path


def fix_secrets(target, framework, dry_run=False, verbose=False):
    target = Path(target)
    outcome = {"fixed": [], "created": [], "warnings": [], "message": ""}

    # Fix .gitignore
    gitignore = target / ".gitignore"
    if not gitignore.exists():
        content = """# Environment
.env
.env.local
.env.*.local

# Dependencies
node_modules/
vendor/

# Build
dist/
build/
.next/
out/
target/

# IDE
.vscode/
.idea/
*.swp
*.swo

# OS
.DS_Store
Thumbs.db

# Logs
*.log
logs/

# Secrets (keep these out)
*.pem
*.key
*.cert
credentials.json
service-account.json
"""
        if not dry_run:
            gitignore.write_text(content)
        outcome["created"].append(".gitignore")
    elif ".env" not in gitignore.read_text():
        if not dry_run:
            with open(gitignore, "a") as f:
                f.write("\n# Environment\n.env\n.env.local\n")
        outcome["fixed"].append(f"Added .env to {gitignore}")
    else:
        outcome["fixed"].append(".gitignore already has .env")

    # Fix .env.example
    env_example = target / ".env.example"
    if not env_example.exists():
        content = """# Application Settings
# Copy this file to .env and fill in your values
# NEVER commit .env to version control

# Node
NODE_ENV=development

# Database
DATABASE_URL=postgresql://user:password@localhost:5432/dbname

# Auth
JWT_SECRET=change-me-to-a-random-secret
SESSION_SECRET=change-me-to-a-random-secret

# API Keys (replace with your own)
# API_KEY=your-api-key-here

# Stripe
# STRIPE_SECRET_KEY=sk_test_...
# STRIPE_WEBHOOK_SECRET=whsec_...

# Third-party
# NEXT_PUBLIC_API_URL=http://localhost:3000
"""
        if not dry_run:
            env_example.write_text(content)
        outcome["created"].append(".env.example")
    else:
        outcome["fixed"].append(".env.example already exists")

    # Check if .env is in .gitignore
    if gitignore.exists():
        gi_content = gitignore.read_text()
        if ".env" not in gi_content:
            if not dry_run:
                with open(gitignore, "a") as f:
                    f.write("\n# Environment\n.env\n.env.local\n")
            outcome["fixed"].append("Added .env to .gitignore")
        else:
            outcome["fixed"].append(".env already in .gitignore")

    return outcome
