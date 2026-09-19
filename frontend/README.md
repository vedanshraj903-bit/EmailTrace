# EmailTrace frontend

React + TypeScript + Vite. Setup and run instructions are in the [main README](../README.md).

```bash
npm install      # once
npm run dev      # http://localhost:5173 (expects the backend on port 8000)
npm run build    # production build into dist/
npm run lint     # oxlint
```

The dev server forwards `/api` to the backend. To point it at a different backend, set
`VITE_API_TARGET=http://host:port` before `npm run dev`.
