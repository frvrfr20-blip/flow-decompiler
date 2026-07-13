local total = 0

for value = 1, 5 do
    if value % 2 == 0 then
        total += value
    else
        total -= value
    end
end

local count = 0
while count < 3 do
    total += count
    count += 1
end

repeat
    total -= 1
until total <= 3

print(total)
