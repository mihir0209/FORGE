from dataclasses import dataclass

@dataclass
class WasmFuelStatus:
    remaining_fuel: int
    fuel_exhausted: bool
    trapped: bool

class WasmFuelMeteringSentinel:
    def __init__(self, initial_fuel: int = 10_000):
        self.remaining_fuel = initial_fuel

    def consume_instruction_fuel(self, instruction_cost: int) -> WasmFuelStatus:
        if self.remaining_fuel < instruction_cost:
            self.remaining_fuel = 0
            return WasmFuelStatus(remaining_fuel=0, fuel_exhausted=True, trapped=True)

        self.remaining_fuel -= instruction_cost
        return WasmFuelStatus(
            remaining_fuel=self.remaining_fuel,
            fuel_exhausted=False,
            trapped=False
        )
