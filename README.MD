<h3>Create a PostgreSQL instance with Docker:</h3>

```console
docker run --name ead-authuser -e POSTGRES_PASSWORD=authuser -e POSTGRES_USER=authuser -e POSTGRES_DB=ead-authuser -p 5432:5432 -d postgres
