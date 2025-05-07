# Ask Otter
![mascot](otter.jpg)

## Instructions
Configure your environment by adding a file `.env` into the root directory.

```env
llm_server=http://localhost:8080
api_key=your_api_key
```

To run the LLM container on CPU, do
```
docker compose up
```

To run the LLM container on GPU, do
```
docker compose -f compose.yaml -f compose.gpu.yaml up
```