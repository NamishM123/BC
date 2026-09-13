"""Convert mustang.jpg to BMP format for encryption."""
from PIL import Image

img = Image.open('mustang.jpg')
img = img.convert('RGB')
img.save('mustang.bmp', 'BMP')
print(f"Created mustang.bmp ({img.size[0]}x{img.size[1]})")
