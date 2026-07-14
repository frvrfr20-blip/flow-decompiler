local function values(seed)
    return seed, seed + 1, seed * 2
end

local first, second, third = values(4)
print(first, second, third)
