
COLOR = {
	'white': '\0030',
	'black': '\0031',
	'blue': '\0032',
	'red': '\0034',
	'dred': '\0035',
	'purple': '\0036',
	'dyellow': '\0037',
	'yellow': '\0038',
	'bgreen': '\0039',
	'dgreen': '\00310',
	'green': '\00311',
	'bpurple': '\00313',
	'dgrey': '\00314',
	'lgrey': '\00315',
	'end': '\003'
}

def add_color(color, text):
    return COLOR[color] + text + COLOR['end']
