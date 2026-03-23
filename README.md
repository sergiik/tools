python3 -m venv .venv
. .venv/bin/activate
pip install requests

python3 harbor_export.py \
  --url https://harbor.example.com \
  --username admin \
  --password 'SuperSecret' \
  --output harbor-full-export.json

  Что ты получишь на выходе:
	•	system_configuration
	•	массив projects
	•	внутри каждого проекта: detail, summary, metadata, members, labels, robots, immutable_tag_rules, webhook_policies, retentions, quotas
	•	блок globals для registries / replication / scanners / system robots / labels
	•	блок errors со всем, что не подошло к твоей версии Harbor или не разрешено твоей учётке
