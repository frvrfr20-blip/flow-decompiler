local total = 0

for value = 1, 8 do
    if value == 7 then
        break
    end
    if value % 2 == 0 then
        continue
    end
    total += value
end

for _, value in ipairs({ 2, 3, 4, 5 }) do
    if value == 4 then
        break
    end
    if value == 2 then
        continue
    end
    total += value
end

local count = 0
while count < 5 do
    count += 1
    if count == 2 then
        continue
    end
    if count == 5 then
        break
    end
    total += count
end

local repeated = 0
repeat
    repeated += 1
    if repeated == 2 then
        continue
    end
    total += repeated
until repeated >= 4

print(total)
