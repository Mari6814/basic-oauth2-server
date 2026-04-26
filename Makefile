.PHONY: lint format test serve admin

test: lint format
	uv run -m pytest --cov=basic_oauth2_server tests/ --cov-report=term-missing --cov-fail-under=99

lint:
	uv run ruff check --fix

format:
	uv run ruff format

serve:
	uv run -m basic_oauth2_server serve \
		 --port 8080 \
		 --host localhost 

admin:
	uv run -m basic_oauth2_server admin \
		 --port 8081 \
		 --host localhost
