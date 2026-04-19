/*
 * Copyright The OpenTelemetry Authors
 * SPDX-License-Identifier: Apache-2.0
 */

package io.opentelemetry.obi.java;

import static org.junit.jupiter.api.Assertions.*;

import io.opentelemetry.obi.java.instrumentations.CallableInst;
import io.opentelemetry.obi.java.instrumentations.JavaExecutorInst;
import io.opentelemetry.obi.java.instrumentations.RunnableInst;
import java.lang.instrument.Instrumentation;
import java.util.Collections;
import java.util.concurrent.*;
import net.bytebuddy.agent.ByteBuddyAgent;
import org.junit.jupiter.api.Test;
import testutil.LambdaFactory;

/**
 * Verifies that dynamic agent attachment does not break lambda classes.
 *
 * <p>On Java 8, lambda classes are VM anonymous classes. Due to JDK-8145964, retransforming them
 * corrupts their constant pool linkage to the host class, causing NoClassDefFoundError. The bug was
 * fixed in Java 9 (anonymous classes became non-modifiable) and is irrelevant on Java 15+ (lambdas
 * are hidden classes).
 *
 * <p>The corruption is triggered by the manual {@code inst.retransformClasses()} loop in {@link
 * Agent#agentmain}, not by ByteBuddy's installOn(). This test replicates that loop, scoped to
 * testutil classes, and verifies lambdas still work afterward.
 *
 * <p>Lambdas come from {@link LambdaFactory} (package testutil), not io.opentelemetry.obi, because
 * Agent.builder() already ignores that package prefix.
 */
class LambdaExclusionTest {

  /**
   * Installs the agent's ByteBuddy transformer, then manually retransforms matching classes (as
   * agentmain does), and verifies lambda classes still work.
   *
   * <p>Without $$Lambda exclusion in Agent.builder(), this throws NoClassDefFoundError on Java 8.
   */
  @Test
  void lambdasWorkAfterAgentAttachment() throws Exception {
    // Phase 1: Create and exercise lambdas before agent attachment.
    // Lambdas come from testutil.LambdaFactory, outside io.opentelemetry.obi,
    // so they won't be ignored by the builder's nameStartsWith("io.opentelemetry.obi") rule.
    Callable<String> callable = LambdaFactory.newCallable("before");
    assertEquals("before", callable.call());

    Runnable runnable = LambdaFactory.newRunnable();
    runnable.run();

    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<String> f = executor.submit(LambdaFactory.newCallable("baseline"));
      assertEquals("baseline", f.get());
    } finally {
      executor.shutdown();
      executor.awaitTermination(5, TimeUnit.SECONDS);
    }

    // Phase 2: Install the agent's ByteBuddy transformer using the actual Agent.builder().
    Instrumentation inst = ByteBuddyAgent.install();

    java.lang.instrument.ClassFileTransformer transformer =
        Agent.builder(Collections.emptyMap(), inst)
            .type(RunnableInst.type())
            .transform(RunnableInst.transformer())
            .type(CallableInst.type())
            .transform(CallableInst.transformer())
            .type(JavaExecutorInst.type())
            .transform(JavaExecutorInst.transformer())
            .installOn(inst);

    try {
      // Phase 3: Manually retransform matching classes, as agentmain() does.
      // Uses Agent.shouldSkipRetransform() — the actual production code — to decide
      // which classes to skip. On Java 8, calling retransformClasses() on $$Lambda
      // classes corrupts them (JDK-8145964), so shouldSkipRetransform() must return
      // true for them. Scoped to testutil to avoid corrupting Gradle's classes.
      for (Class<?> clazz : inst.getAllLoadedClasses()) {
        if (!clazz.getName().startsWith("testutil.")) {
          continue;
        }
        if (Agent.shouldSkipRetransform(clazz)) {
          continue;
        }
        if (JavaExecutorInst.matches(clazz)
            || CallableInst.matches(clazz)
            || RunnableInst.matches(clazz)) {
          try {
            inst.retransformClasses(clazz);
          } catch (Throwable t) {
            // Some classes can't be retransformed — that's expected
          }
        }
      }

      // Phase 4: Exercise lambdas after retransformation.
      // If lambda classes were corrupted by retransformClasses() in Phase 3, this throws:
      //   java.lang.NoClassDefFoundError: testutil/LambdaFactory$$Lambda$XX
      executor = Executors.newSingleThreadExecutor();
      try {
        Future<String> f = executor.submit(LambdaFactory.newCallable("after-attach"));
        assertEquals("after-attach", f.get());

        executor.submit(LambdaFactory.newRunnable()).get();
      } finally {
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
      }
    } finally {
      inst.removeTransformer(transformer);
    }
  }
}
