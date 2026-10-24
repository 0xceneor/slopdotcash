export interface RegistryDatabase {
  database_name: string;
  database_id: string;
}
export function parseRegistryDatabase(toml: string): RegistryDatabase;
export function readRegistryDatabase(): Promise<RegistryDatabase>;
export function parseMonthlySchedule(toml: string): string;
export function readMonthlySchedule(): Promise<string>;
