/* Vendored STUB of the libpq surface the fixture exercises. */
#ifndef FIXTURE_LIBPQ_FE_H
#define FIXTURE_LIBPQ_FE_H

typedef struct pg_conn PGconn;
typedef struct pg_result PGresult;

PGconn *PQconnectdb(const char *conninfo);
PGresult *PQexec(PGconn *conn, const char *query);
void PQclear(PGresult *res);

#endif /* FIXTURE_LIBPQ_FE_H */
