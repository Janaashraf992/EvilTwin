ls -la
cd /opt/app
cat .env
systemctl status app
aws s3 ls --profile prod-deploy
cat /home/deploy/.aws/credentials
psql "postgresql://app@10.0.1.50:5432/customers" -c '\dt'
mysqldump --single-transaction customers > /var/backups/db/prod_db_dump.sql
scp /var/backups/db/prod_db_dump.sql backup-svc@10.0.1.60:/srv/backups/
df -h
sudo -l
exit
