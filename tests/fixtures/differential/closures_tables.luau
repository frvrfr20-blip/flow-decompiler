local state = { value = 1 }

local function make_adder(step)
    local captured = step
    return function(multiplier)
        state.value += captured
        return state.value * multiplier
    end
end

local add = make_adder(2)
print(add(3))
print(state.value)
