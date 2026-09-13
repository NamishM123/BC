"""Create a sample BMP image with repeating patterns to demonstrate ECB vs CBC."""
from PIL import Image

img = Image.new('RGB', (200, 200))
pixels = img.load()
for y in range(200):
    for x in range(200):
        if (x // 20 + y // 20) % 2 == 0:
            pixels[x, y] = (255, 255, 255)
        else:
            pixels[x, y] = (0, 0, 128)

img.save('sample.bmp', 'BMP')
print("Created sample.bmp")
