// It configures the metrics router
package api

import (
	"github.com/labstack/echo/v4"
	"github.com/labstack/gommon/log"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"io"
	"net/http"
	httpprof "net/http/pprof"
	"runtime"
	//#nosec G108 - exposing the profiling endpoint is expected
	_ "net/http/pprof"

	"contrib.go.opencensus.io/exporter/prometheus"
	promclient "github.com/prometheus/client_golang/prometheus"
)

// ConfigMetricsRouter Configuring the metrics router.
// > ConfigMetricsRouter is a function that takes a pointer to an echo.Group and returns nothing
func ConfigMetricsRouter(e *echo.Group) {
	// metrics
	phandle := promhttp.Handler()
	e.GET("/debug/metrics/prometheus", func(e echo.Context) error {
		phandle.ServeHTTP(e.Response().Writer, e.Request())

		return nil
	})

	e.GET("/debug/metrics", func(e echo.Context) error {
		return e.JSON(http.StatusOK, "Ok")
		//return nil
	})

	e.GET("/debug/metrics", func(e echo.Context) error {
		Exporter().ServeHTTP(e.Response().Writer, e.Request())
		return nil
	})
	e.GET("/debug/stack", func(e echo.Context) error {
		err := WriteAllGoroutineStacks(e.Response().Writer)
		if err != nil {
			log.Error(err)
		}
		return err
	})

	e.GET("/debug/pprof/:prof", ServeProfile) // Upload for testing
}

// It creates a Prometheus exporter that exports the metrics from the default Prometheus registry
func Exporter() http.Handler {
	// Prometheus globals are exposed as interfaces, but the prometheus
	// OpenCensus exporter expects a concrete *Registry. The concrete type of
	// the globals are actually *Registry, so we downcast them, staying
	// defensive in case things change under the hood.
	registry, ok := promclient.DefaultRegisterer.(*promclient.Registry)
	if !ok {
		log.Warnf("failed to export default prometheus registry; some metrics will be unavailable; unexpected type: %T", promclient.DefaultRegisterer)
	}
	exporter, err := prometheus.NewExporter(prometheus.Options{
		Registry:  registry,
		Namespace: "delta",
	})
	if err != nil {
		log.Errorf("could not create the prometheus stats exporter: %v", err)
	}

	return exporter
}

// It takes a URL parameter, and then serves the corresponding profile
// It takes a URL parameter, and if it's one of the supported profiling types, it serves the profile data
func ServeProfile(c echo.Context) error {
	httpprof.Handler(c.Param("prof")).ServeHTTP(c.Response().Writer, c.Request())
	return nil
}

// It writes the stack traces of all goroutines to the given writer
func WriteAllGoroutineStacks(w io.Writer) error {
	buf := make([]byte, 64<<20)
	for i := 0; ; i++ {
		n := runtime.Stack(buf, true)
		if n < len(buf) {
			buf = buf[:n]
			break
		}
		if len(buf) >= 1<<30 {
			// Filled 1 GB - stop there.
			break
		}
		buf = make([]byte, 2*len(buf))
	}
	_, err := w.Write(buf)
	return err
}
