from dataclasses import dataclass
from cryptography.hazmat.primitives.asymmetric import rsa

@dataclass
class Key:
    key_public : None = object
    key_private : None = object

class Shifr():

    def __init__(self):
        self.key = Key()
        

    def Сreature_key(self):
        key = rsa.generate_private_key(
        public_exponent=65537,  # распространённый выбор для открытого экспонента
        key_size=2048  # рекомендуемая длина ключа
        )   
        self.key.key_private = key
        self.key.key_public = key.public_key()

    def Get_key(self):
        # print([self.key.key_private,self.key.key_public])
        return [self.key.key_private,self.key.key_public]

if __name__ == '__main__':
    Shifr_rsa = Shifr()
    Shifr_rsa.Сreature_key()
    Shifr_rsa.Get_key()