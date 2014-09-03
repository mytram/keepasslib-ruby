require 'openssl'

key = 'a49c6355716612dd3ae7760246f86432cc2ab98a56c7c983b57fbd542172ae'
iv = 'c13ab829d052fb56841ffa5479cbc32'

cipher = OpenSSL::Cipher.new('AES-256-CBC')
cipher.encrypt
# key = cipher.random_key
# iv = cipher.random_iv
cipher.key = key
cipher.iv = iv
data = 'Hello world'
# puts data.length
encrypted =  cipher.update(data) + cipher.final

def ba_s(data)
  str = ''
  data.bytes.each do |i|
    str += i.to_s(16)
  end
  str
end

cipher_text = 'fa527ed132a99527ed1ef3c6ffce98d'
cipher_text = encrypted
cipher.reset
cipher.decrypt

key = key.pack("H*")

cipher.key = key
cipher.iv = iv
plain = cipher.update(cipher_text) + cipher.final

puts plain

puts ba_s(encrypted)
puts encrypted.length

