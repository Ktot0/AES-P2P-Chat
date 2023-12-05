from random import randint
import miller_rabin as mr


def greatest_common_divisor(x, y) -> int:
   while y:
      x, y = y, x % y
   return x

if __name__ == "__main__":
   accuracy = 4 
   min_q = int('1' * 128)
   max_q = int('9' * 128)

   q = randint(min_q, max_q)
   while not mr.test_prime(q, accuracy):
       q = randint(min_q, max_q)

   for k in range(2, q - 1, 1):
       if greatest_common_divisor(k, q - 1) == 1:
           alpha = k
           break

   with open("qalpha", "w") as f:
       f.write(str(q) + "," + str(alpha))

