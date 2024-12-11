lines = open('maze.txt').readlines()[2:]
maze = bytes(int(line.split()[1]) for line in lines)

print(maze)
