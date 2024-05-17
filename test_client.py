import asyncio
import websockets

async def test_websocket():
    uri = "ws://127.0.0.1:8000/ws"
    async with websockets.connect(uri) as websocket:
        while True:
            response = await websocket.recv()
            print(f"Received result: {response}")

asyncio.run(test_websocket())
