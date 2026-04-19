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

/**
 * Verifies that dynamic agent attachment does not break lambda classes.
 *
 * <p>On Java 8-14, lambda classes are VM anonymous classes. When ByteBuddy retransforms them during
 * dynamic attachment (agentmain), it corrupts them because they don't have class file bytes
 * accessible through a ClassLoader. This causes NoClassDefFoundError at runtime.
 *
 * <p>On Java 15+, lambdas are hidden classes that the JVM itself protects from retransformation, so
 * the test passes regardless. The $$Lambda exclusion is still needed for Java 8-14 support.
 *
 * <p>This test calls Agent.builder() directly, so the builder's ignore rules determine whether
 * lambda classes are protected. Without .ignore(nameContains("$$Lambda")) in Agent.builder(), this
 * test fails on Java 8 with NoClassDefFoundError.
 */
class LambdaExclusionTest {

  /**
   * Simulates the agent's dynamic attachment flow (agentmain) using the actual Agent.builder(), and
   * verifies that lambda classes still work afterward.
   *
   * <p>Without $$Lambda exclusion in Agent.builder(), this throws NoClassDefFoundError on Java 8.
   */
  @Test
  void lambdasWorkAfterAgentAttachment() throws Exception {
    // Phase 1: Create and exercise lambdas before agent attachment
    Callable<String> callable = () -> "before";
    assertEquals("before", callable.call());

    ExecutorService executor = Executors.newSingleThreadExecutor();
    try {
      Future<String> f = executor.submit(() -> "baseline");
      assertEquals("baseline", f.get());
    } finally {
      executor.shutdown();
      executor.awaitTermination(5, TimeUnit.SECONDS);
    }

    // Phase 2: Install the agent's ByteBuddy transformer using the actual Agent.builder().
    // If Agent.builder() doesn't ignore $$Lambda classes, ByteBuddy will attempt to
    // retransform them when installOn triggers RETRANSFORMATION of loaded classes.
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
      // Phase 3: Retransform all matching classes, including lambdas.
      // This simulates the agentmain() retransformation loop without any skip logic,
      // so the only protection is Agent.builder()'s ignore rules.
      for (Class<?> clazz : inst.getAllLoadedClasses()) {
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

      // Phase 4: Exercise lambdas after agent attachment.
      // If $$Lambda classes were corrupted by retransformation, this throws:
      //   java.lang.NoClassDefFoundError: LambdaExclusionTest$$Lambda$XX
      executor = Executors.newSingleThreadExecutor();
      try {
        Future<String> f = executor.submit(() -> "after-attach");
        assertEquals("after-attach", f.get());

        executor.submit((Runnable) () -> {}).get();
      } finally {
        executor.shutdown();
        executor.awaitTermination(5, TimeUnit.SECONDS);
      }
    } finally {
      inst.removeTransformer(transformer);
    }
  }
}
