-- This migration introspects the _sqlx_migrations table and removes the broken
-- and replaced migrations which conflict with CoLTE. It is somewhat of a hack,
-- and will eventually not be needed once haulage and colte are completely
-- isolated.

DELETE FROM _sqlx_migrations
WHERE
    "checksum"='\x76a282198f383ccc059afcc193db4b816f5ceab9fb58e4844ff8fcd7c0c93b81c04c98c067457e07541e3cd182180049'
    AND "version"=20210629184727;

DELETE FROM _sqlx_migrations
WHERE
    "checksum"='\x69ac7dadf2d9a9abe0e44c2a830bf0636c08d611bc8df0b4e813584655754386fa23ea97d81f1150a80b0cd8e23c6c8d'
    AND "version"=20210723202906;
