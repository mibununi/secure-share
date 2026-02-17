import { Contract } from "fabric-contract-api";
import { FilesContract } from "./filesContract";

export const contracts: typeof Contract[] = [FilesContract];