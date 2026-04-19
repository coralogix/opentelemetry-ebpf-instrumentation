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
 * <p>This test calls Agent.builder() directly. The builder's .ignore() rules determine whether
 * lambda classes are protected. Without .ignore(nameContains("$$Lambda")) in Agent.builder(), this
 * test fails on Java 8 with NoClassDefFoundError.
 *
 * <p>Note: lambdas are created via {@link LambdaFactory} which lives outside the
 * io.opentelemetry.obi package, because Agent.builder() already ignores that package prefix.
 */
class LambdaExclusionTest {

  /**
   * Installs the agent's ByteBuddy transformer using the actual Agent.builder() with
   * RETRANSFORMATION strategy, which retransforms all already-loaded matching classes. Then
   * exercises lambda classes to verify they weren't corrupted.
   *
   * <p>Without $$Lambda exclusion in Agent.builder(), this throws NoClassDefFoundError on Java 8.
   */
  @Test
  void lambdasWorkAfterAgentAttachment() throws Exception {
    // Phase 1: Create and exercise lambdas before agent attachment.
    // Lambdas are from LambdaFactory (package testutil), not io.opentelemetry.obi,
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
    // The RETRANSFORMATION strategy causes ByteBuddy to retransform all already-loaded classes
    // that match the type matchers. On Java 8 without the $$Lambda ignore rule, this includes
    // the LambdaFactory lambda classes, which corrupts them due to JDK-8145964.
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
      // Phase 3: Exercise lambdas after agent attachment.
      // If lambda classes were corrupted by the RETRANSFORMATION triggered in installOn(),
      // this throws: java.lang.NoClassDefFoundError: testutil/LambdaFactory$$Lambda$XX
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
