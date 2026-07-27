# CPE Validation Frontend

React interface for browsing the Docker Official Image inventory used by the
CPE Validation research pilot. The current UI covers the image inventory and
the read-only Primary CPE Component validation queue.

## Supported environment

- Desktop research workstation
- Recommended browser width: 1280px or wider
- Fixed navigation sidebar and wide evidence tables
- Mobile-specific UI is not supported

Tables retain horizontal scrolling and long evidence values wrap so narrower
desktop windows and unusually long CPE, PURL, bom-ref, and path values do not
break the layout.

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

## Routes

- `/images` — Docker Official Image inventory
- `/components` — Primary CPE Component list

The Components route supports these query parameters:

- `image_id` — limit results to one Docker image
- `search` — server-side Component search
- `ordering` — server-side sort field and direction
- `page` — page number
- `page_size` — one of 25, 50, 100, or 200
- `component_id` — open one read-only Component Detail panel

For example:

<http://127.0.0.1:5173/components?image_id=1&component_id=101>

The application uses `BrowserRouter`. A production static host must provide
an SPA fallback that serves `index.html` for frontend routes such as
`/images` and `/components`. Production web server configuration is outside
the current scope.

## Quality checks

```bash
npm run lint
npm run test:run
npm run build
```

Use `npm test` for Vitest watch mode.

## Current scope

The Images screen provides API health, pilot summary metrics, client-side
search, and a sortable image table with Primary CPE Coverage. Selecting an
image opens its Component queue.

The Components screen provides an image scope summary plus server-side
search, sorting, page-size selection, and pagination for Components with a
Primary CPE. Selecting a Component row opens a read-only evidence panel with
Component metadata, the Primary CPE and all CPE 2.3 fields, structural status,
Syft candidate properties, other SBOM properties, and SBOM source metadata.
The `component_id` URL state restores the same selection after reload.

The Detail panel is evidence inspection only; it is not a Ground Truth
decision screen. Official CPE Dictionary exact matching, Ground Truth review,
manual decision storage, candidate ranking, Validation Workbench, review
history, authentication, exports, and frontend containerization are not
implemented in this phase.
