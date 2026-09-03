/** One buffered host wakeup for a polling loop. */
export class WakeSignal {
  private pending = false;
  private finish: (() => void) | undefined;

  public notify(): void {
    if (this.finish === undefined) {
      this.pending = true;
      return;
    }
    this.finish();
  }

  public wait(signal: AbortSignal, intervalMs: number): Promise<void> {
    if (this.pending) {
      this.pending = false;
      return Promise.resolve();
    }
    if (signal.aborted) return Promise.resolve();
    return new Promise((resolve) => {
      let timer: ReturnType<typeof setTimeout>;
      const finish = (): void => {
        clearTimeout(timer);
        signal.removeEventListener("abort", finish);
        if (this.finish === finish) this.finish = undefined;
        resolve();
      };
      timer = setTimeout(finish, intervalMs);
      this.finish = finish;
      signal.addEventListener("abort", finish, { once: true });
    });
  }
}
