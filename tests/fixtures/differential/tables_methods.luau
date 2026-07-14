local ledger = { total = 0, entries = {} }
local alias = ledger

function ledger:record(value)
    self.total += value
    self.entries[#self.entries + 1] = self.total
    return self.total
end

local first = alias:record(3)
alias.total *= 2
local second = ledger:record(4)

print(first, second, table.concat(ledger.entries, ","), alias.total)
