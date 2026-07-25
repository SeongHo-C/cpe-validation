# CPE Validation Frontend

React interface for browsing the Docker Official Image inventory used by the
CPE Validation research pilot. The current UI covers the image inventory only.

## Technology

- React and TypeScript
- Vite
- Tailwind CSS with the Vite integration
- shadcn/ui
- TanStack React Table
- Vitest and React Testing Library

## Prerequisites

- Node.js 22 or another version supported by the installed Vite release
- npm
- The Django backend dependencies installed in `backend/.venv`
- The PostgreSQL Compose service running and healthy

## Install

From the repository root:

```bash
cd frontend
npm ci
```

## Development

Start the backend from the repository root:

```bash
backend/.venv/bin/python backend/manage.py runserver 127.0.0.1:8000
```

Start Vite in another terminal:

```bash
cd frontend
npm run dev
```

Open <http://127.0.0.1:5173>. Browser requests use relative `/api/...`
paths. Vite proxies `/api` to the Django server at
`http://127.0.0.1:8000` without rewriting the path, so Django CORS changes
are not required.

## Quality checks

```bash
npm run lint
npm run test:run
npm run build
```

Use `npm test` for Vitest watch mode.

## Current scope

The Images screen provides API health, pilot summary metrics, client-side
search, and a sortable image table with Primary CPE Coverage. Components and
Workbench navigation entries are intentionally disabled.

Component browsing, validation workflows, CPE Dictionary matching, review
history, authentication, exports, and frontend containerization are not
implemented in this phase.
