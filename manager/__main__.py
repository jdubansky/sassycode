import os
import argparse
import uvicorn


def main(argv=None):
    parser = argparse.ArgumentParser(description="Run sassycode manager server")
    parser.add_argument("--host", default=os.getenv("HOST", "127.0.0.1"))
    parser.add_argument("--port", type=int, default=int(os.getenv("PORT", "3000")))
    parser.add_argument("--reload", action="store_true", default=True)
    args = parser.parse_args(argv)

    uvicorn.run("manager.app:app", host=args.host, port=args.port, reload=args.reload)


if __name__ == "__main__":
    main()


