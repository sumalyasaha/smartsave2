# Running the app with Docker and Docker Desktop

## Prerequisites

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) installed and running (includes Docker Engine and Docker Compose).

## Option 1: App + MySQL with Docker Compose (recommended)

Builds the app image, starts MySQL, runs the schema, then starts the app.

```bash
# From the project root (smartsave2)
docker-compose up --build
```

- **App:** http://localhost:3000  
- **MySQL:** localhost:3306 (user `smartsave`, password `smartsave`, database `smartsave`)

To run in the background:

```bash
docker-compose up --build -d
```

Stop and remove containers:

```bash
docker-compose down
```

## Option 2: Build and run the app image only

Use this when you already have MySQL running (e.g. on the host or elsewhere).

**1. Build the image**

```bash
docker build -t smartsave-app .
```

**2. Run the container**

```bash
docker run -p 3000:3000 \
  -e DATABASE_URL=mysql://smartsave:smartsave@host.docker.internal:3306/smartsave \
  -e JWT_SECRET=your-secret \
  -e NODE_ENV=production \
  smartsave-app
```

- `host.docker.internal` points to your host machine from inside the container (Docker Desktop). Use it if MySQL is on your Mac/PC.
- If MySQL is in another container or server, use that hostname or IP instead of `host.docker.internal`.

## Using Docker Desktop

1. Open **Docker Desktop** and wait until it’s running (whale icon in the menu bar).
2. Open a terminal in the project folder and run:
   ```bash
   docker-compose up --build
   ```
3. In Docker Desktop, go to **Containers** to see the running app and MySQL containers, view logs, or stop them.
4. To inspect the app image: **Images** → find `smartsave2-app` (or the name shown after `docker compose build`).

## Optional: custom JWT secret

Create a `.env` file in the project root (or set the variable in your shell):

```
JWT_SECRET=your-secure-secret
```

Then run:

```bash
docker-compose up --build
```

Compose will pass `JWT_SECRET` into the app container.
