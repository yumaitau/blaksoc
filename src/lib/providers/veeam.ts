import { veeamHealth, type VeeamConfig } from "@/lib/backup/status";

/** Veeam backup jobs. This build only accepts fixture config. */
export class VeeamProvider {
  readonly kind = "veeam";

  constructor(private readonly config: VeeamConfig) {}

  async health() {
    return veeamHealth(this.config);
  }
}
