// A local BARREL (po-pk3fp.10): clients are constructed or re-exported here and
// imported everywhere else, which is how most services are laid out. The
// TypeChecker follows these re-exports whether or not node_modules exists,
// because they are the repo's own modules; the syntactic fallback has to
// follow them too, or every site below resolves nothing on an uninstalled tree.
import Redis from 'ioredis';

export { Pool as PgPool } from 'pg';
export { boundedPool } from './dbconfig';

export default new Redis({ connectTimeout: 500 });
