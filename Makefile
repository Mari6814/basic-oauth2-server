.PHONY: lint format test serve admin

lint:
	uv run ruff check --fix

format:
	uv run ruff format

test:
	uv run -m pytest tests/

serve:
	uv run -m basic_oauth2_server serve \
		 --port 8080 \
		 --host localhost 

admin:
	uv run -m basic_oauth2_server admin \
		 --port 8081 \
		 --host localhost
