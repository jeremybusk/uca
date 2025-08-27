psql < insert.default.encryption.sql 
psql < create.ca.sql
select id from certificate_authorities;
update id uuid in issue.cert.sql
psql < issue.cert.sql (needs better debug if id not exists etc)
