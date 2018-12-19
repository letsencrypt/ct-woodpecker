#!/bin/bash
dnf install -y jq

host=grafana
port=3000
for n in $(seq 1 60); do
    if exec 6<>/dev/tcp/${host}/${port}; then
        break
    else
        echo "Trying to connect to ${host}:${port}"
        sleep 1
    fi

    if [ "$n" -eq 60 ]; then
        echo "Unable to connect to ${host}"
        exit 1
    fi
done

exec 6>&- > /dev/null
echo "Connected to ${host}:${port}"
sleep 5

DASH_ID=$(curl http://${GF_SECURITY_ADMIN_USER}:${GF_SECURITY_ADMIN_PASSWORD}@10.40.50.6:3000/api/dashboards/db/ct-woodpecker | jq -r '.dashboard.id')

if [ "$(curl -s http://${GF_SECURITY_ADMIN_USER}:${GF_SECURITY_ADMIN_PASSWORD}@10.40.50.6:3000/api/dashboards/db/ct-woodpecker | jq -r '.meta.isStarred')" != "true" ]; then
    # Star the ct-woodpecker dashboard only if it hasn't already been starred
    curl -X POST http://${GF_SECURITY_ADMIN_USER}:${GF_SECURITY_ADMIN_PASSWORD}@10.40.50.6:3000/api/user/stars/dashboard/${DASH_ID}

    # Set the starred dashboard as the home dashboard so that it opens automatically when you access grafana
    curl -X PUT \
        -H 'Content-Type: application/json' \
        -d "{\"theme\": \"dark\",\"homeDashboardId\": ${DASH_ID},\"timezone\": \"utc\"}" \
        http://${GF_SECURITY_ADMIN_USER}:${GF_SECURITY_ADMIN_PASSWORD}@10.40.50.6:3000/api/org/preferences
fi

echo "Open http://localhost:3000 to view the ct-woodpecker dashboard"
