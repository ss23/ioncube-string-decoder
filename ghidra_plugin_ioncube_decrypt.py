# Decrypts "encrypted" strings from ioncube's loaders
#@author ss23
#@category _NEW_
#@keybinding 
#@menupath 
#@toolbar 

encryption_key = [0x25,0x68,0xd3,0xc2,0x28,0xf2,0x59,0x2e,0x94,0xee,0xf2,0x91,0xac,0x13,0x96,0x95]

def attemptDecrypt(addr):
	tmplength = getByte(addr)
	if tmplength < 0:
		length = tmplength + 256
	else:
		length = tmplength
	#print length
	content = getBytes(addr.next(), length)

	# Convert negatives into positives
	# TODO: Surely there's an API call for this
	new_content = []
	for i in range(0, length):
		# jython why
		if content[i] < 0:
			new_content.append(content[i] + 256)
		else:
			new_content.append(content[i])

	decrypted_string = ""

	# Decrypt the content
	for i in range(0, length):
		decrypted_string  += chr(new_content[i] ^ encryption_key[(length + i) % len(encryption_key)])
	
	return decrypted_string

funcs = getGlobalFunctions("ioncube_decrypt")
if len(funcs) < 1:
	print "Could not identify ioncube_decrypt function"
	exit()
elif len(funcs) > 1:
	print "Too many ioncube_decrypt functions identified"
	exit()


refs = getReferencesTo(funcs[0].getEntryPoint())
for ref in refs:
	addr = ref.getFromAddress()
	# instruction before should be the "push encrypted_string" we want
	instr = getInstructionBefore(addr)
	if (type(instr) == type(None)):
		continue
	possible_data_addr = instr.getOpObjects(0)[0]

	# Java!
	addr_factory = getAddressFactory()
	# Get the assumed-length
	possible_data_addr_str = possible_data_addr.toString()
	possible_data_addr = addr_factory.getAddress(possible_data_addr_str)	

	decrypted_string = attemptDecrypt(possible_data_addr)

	# TODO: Figure out how to set repeatable comments on a symbol / address
	# TODO: Do not duplicate comments
	setPreComment(possible_data_addr, "decrypted: " + decrypted_string)

	#print possible_data_addr

print "Completed"

