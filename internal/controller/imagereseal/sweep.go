package imagereseal

import (
	"context"
	"time"

	"github.com/centos-automotive-suite/automotive-dev-operator/internal/common/sealedsecrets"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

const (
	// orphanSweepInterval is how often the controller looks for transient
	// Secrets whose ImageReseal no longer exists.
	orphanSweepInterval = 5 * time.Minute
)

// sweepOrphanedTransientSecrets removes transient Secrets left behind by
// sealed-image requests whose ImageReseal is gone.
func (r *Reconciler) sweepOrphanedTransientSecrets(ctx context.Context) error {
	_, err := sealedsecrets.SweepOrphaned(ctx, r.Client, log.FromContext(ctx), sealedsecrets.OrphanGracePeriod)
	return err
}

// Start implements manager.Runnable. It sweeps at startup and then on a timer
// so an orphan is removed even when no ImageReseal event ever arrives for it.
func (r *Reconciler) Start(ctx context.Context) error {
	logger := r.Log.WithName("sealed-secret-sweep")
	ctx = log.IntoContext(ctx, logger)

	runSweep := func() {
		deleted, err := sealedsecrets.SweepOrphaned(ctx, r.Client, logger, sealedsecrets.OrphanGracePeriod)
		if err != nil {
			logger.Error(err, "Orphaned transient Secret sweep incomplete; will retry", "deleted", deleted)
			return
		}
		if deleted > 0 {
			logger.Info("Removed orphaned transient Secrets", "count", deleted)
		}
	}

	runSweep()
	ticker := time.NewTicker(orphanSweepInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			runSweep()
		}
	}
}
